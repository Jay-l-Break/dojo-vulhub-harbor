#!/bin/sh
set -eu
attempt=0
while [ "$attempt" -lt 180 ]; do
  if (
    cd /opt/jumpserver/apps
    /opt/py3/bin/python3 manage.py shell -c 'from users.models import User; user = User.objects.get(username='"'"'admin'"'"'); user.set_unusable_password(); user.save(update_fields=['"'"'password'"'"']); user.refresh_from_db(); assert not user.has_usable_password()'
  ); then
    /bin/sh /run/dojo-seed/install.sh
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 2
done
exit 1
