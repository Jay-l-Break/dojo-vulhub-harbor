package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddress = "127.0.0.1:4444"
	defaultOracleSocket  = "/run/dojo-oracle/oracle.sock"
	defaultHelperPath    = "/run/oracle-proof/helper"
	defaultTimeout       = 10 * time.Second
	maxConcurrentShells  = 32
	maxOracleResponse    = 16 * 1024
	maxShellLine         = 64 * 1024
	markerPrefix         = "DOJO_RCE_PROOF_"
	schemaVersion        = "1.0"
)

var markerCandidatePattern = regexp.MustCompile(markerPrefix + `[0-9a-f]{64}`)

type oracleRequest struct {
	SchemaVersion string `json:"schema_version"`
	Action        string `json:"action"`
	Nonce         string `json:"nonce"`
	Marker        string `json:"marker,omitempty"`
	Proof         string `json:"proof,omitempty"`
}

type oracleResponse struct {
	SchemaVersion string `json:"schema_version"`
	Accepted      bool   `json:"accepted"`
	Marker        string `json:"marker,omitempty"`
	Error         string `json:"error,omitempty"`
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func timeoutFromEnvironment() time.Duration {
	value := os.Getenv("DOJO_RCE_TIMEOUT_SEC")
	if value == "" {
		return defaultTimeout
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds < 1 || seconds > 60 {
		return defaultTimeout
	}
	return time.Duration(seconds) * time.Second
}

func freshNonce() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func validNonce(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func oracleRoundTrip(
	socketPath string,
	request oracleRequest,
	timeout time.Duration,
) (oracleResponse, error) {
	connection, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return oracleResponse{}, fmt.Errorf("connect oracle socket: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return oracleResponse{}, fmt.Errorf("set oracle deadline: %w", err)
	}
	encoder := json.NewEncoder(connection)
	if err := encoder.Encode(request); err != nil {
		return oracleResponse{}, fmt.Errorf("send oracle request: %w", err)
	}
	limited := io.LimitReader(connection, maxOracleResponse)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var response oracleResponse
	if err := decoder.Decode(&response); err != nil {
		return oracleResponse{}, fmt.Errorf("decode oracle response: %w", err)
	}
	if response.SchemaVersion != schemaVersion {
		return oracleResponse{}, errors.New("oracle returned an invalid schema")
	}
	return response, nil
}

func proveExecution(nonce string) error {
	if !validNonce(nonce) {
		return errors.New("nonce must be 32 lowercase hexadecimal bytes")
	}
	socketPath := envOrDefault("DOJO_ORACLE_SOCKET", defaultOracleSocket)
	response, err := oracleRoundTrip(
		socketPath,
		oracleRequest{
			SchemaVersion: schemaVersion,
			Action:        "begin",
			Nonce:         nonce,
		},
		timeoutFromEnvironment(),
	)
	if err != nil {
		return err
	}
	if !response.Accepted || !strings.HasPrefix(response.Marker, markerPrefix) {
		return fmt.Errorf("oracle rejected execution proof: %s", response.Error)
	}
	fmt.Println(response.Marker)
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func markerBoundary(value byte) bool {
	return !((value >= 'a' && value <= 'z') ||
		(value >= 'A' && value <= 'Z') ||
		(value >= '0' && value <= '9') || value == '_')
}

func uniqueMarker(line string) (string, bool) {
	indices := markerCandidatePattern.FindAllStringIndex(line, -1)
	matches := make([]string, 0, len(indices))
	for _, index := range indices {
		if index[0] > 0 && !markerBoundary(line[index[0]-1]) {
			continue
		}
		if index[1] < len(line) && !markerBoundary(line[index[1]]) {
			continue
		}
		matches = append(matches, line[index[0]:index[1]])
	}
	if len(matches) != 1 {
		return "", false
	}
	return matches[0], true
}

func confirmationProof(nonce string, marker string) (string, error) {
	encodedSecret := os.Getenv("DOJO_RCE_CONFIRM_SECRET")
	secret, err := hex.DecodeString(encodedSecret)
	if err != nil || len(secret) != 32 {
		return "", errors.New("listener confirmation secret is invalid")
	}
	mac := hmac.New(sha256.New, secret)
	if _, err := io.WriteString(mac, nonce+"\x00"+marker); err != nil {
		return "", fmt.Errorf("build listener confirmation: %w", err)
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func confirmMarker(nonce string, marker string) error {
	proof, err := confirmationProof(nonce, marker)
	if err != nil {
		return err
	}
	socketPath := envOrDefault("DOJO_ORACLE_SOCKET", defaultOracleSocket)
	response, err := oracleRoundTrip(
		socketPath,
		oracleRequest{
			SchemaVersion: schemaVersion,
			Action:        "confirm",
			Nonce:         nonce,
			Marker:        marker,
			Proof:         proof,
		},
		timeoutFromEnvironment(),
	)
	if err != nil {
		return err
	}
	if !response.Accepted {
		return fmt.Errorf("oracle rejected marker: %s", response.Error)
	}
	return nil
}

func handleReverseShell(connection net.Conn) {
	defer connection.Close()
	timeout := timeoutFromEnvironment()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return
	}
	nonce, err := freshNonce()
	if err != nil {
		return
	}
	helperPath := envOrDefault("DOJO_HELPER_PATH", defaultHelperPath)
	command := fmt.Sprintf("%s %s\n", shellQuote(helperPath), nonce)
	if _, err := io.WriteString(connection, command); err != nil {
		return
	}
	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 4096), maxShellLine)
	for scanner.Scan() {
		marker, ok := uniqueMarker(scanner.Text())
		if !ok {
			continue
		}
		if err := confirmMarker(nonce, marker); err == nil {
			return
		}
	}
}

func listenForReverseShells() error {
	address := envOrDefault("DOJO_RCE_LISTEN", defaultListenAddress)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for reverse shells: %w", err)
	}
	defer listener.Close()
	connectionSlots := make(chan struct{}, maxConcurrentShells)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept reverse shell: %w", err)
		}
		select {
		case connectionSlots <- struct{}{}:
			go func() {
				defer func() { <-connectionSlots }()
				handleReverseShell(connection)
			}()
		default:
			connection.Close()
		}
	}
}

func run(arguments []string) error {
	if len(arguments) != 1 {
		return errors.New("usage: helper listen | helper <fresh_nonce>")
	}
	if arguments[0] == "listen" {
		return listenForReverseShells()
	}
	return proveExecution(arguments[0])
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
