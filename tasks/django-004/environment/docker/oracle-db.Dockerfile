FROM vulhub/oracle:12c-ee@sha256:abe33a2b9fc36ad01d364ac61c87eadae90e3bf857c72bcc81de8480b037227f
ENV INIT_MEM_MB=2560

RUN set -eu; \
    entrypoint=/entrypoint.sh; \
    expected_sha256=174780d6c593c3363b22ded6ca41e9dca49c646ceba005efb42c11292dc80e8d; \
    actual_sha256="$(sha256sum "$entrypoint" | cut -d' ' -f1)"; \
    test "$actual_sha256" = "$expected_sha256"; \
    old_token='-memoryPercentage $INIT_MEM_PST'; \
    new_token='-totalMemory ${INIT_MEM_MB}'; \
    old_count="$(grep -Fc -- "$old_token" "$entrypoint")"; \
    test "$old_count" -eq 1; \
    sed 's|-memoryPercentage $INIT_MEM_PST|-totalMemory ${INIT_MEM_MB}|' \
        "$entrypoint" > "$entrypoint.patched"; \
    ! grep -Fq -- "$old_token" "$entrypoint.patched"; \
    test "$(grep -Fc -- "$new_token" "$entrypoint.patched")" -eq 1; \
    cat "$entrypoint.patched" > "$entrypoint"; \
    rm "$entrypoint.patched"
