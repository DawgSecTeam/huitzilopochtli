#!/bin/sh
# Rosemoor prep 04/05 -- the GlassBoard dashboard: deploy, environment file,
# vendor plugins directory, systemd unit, smoke test. The nakon plants then
# loosen the environment file's mode and the plugins directory's mode on top
# of this (those are findings; the app must keep working through them).
set -eu

# -- app directory (root-owned, readable by the service account) --------------
install -d -o root -g glasssvc -m 0750 /opt/glassboard
install -o root -g glasssvc -m 0640 /root/rosemoor-prep/app.py /opt/glassboard/app.py

cat > /root/rosemoor-prep/glassboard.env <<'EOF'
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=glassapp
DB_PASS=GlassDB-2026!
DB_NAME=glassboard
REDIS_URL=redis://127.0.0.1:6379/0
EOF
install -o root -g glasssvc -m 0640 /root/rosemoor-prep/glassboard.env /opt/glassboard/.env

# -- the vendor "hot-reload" plugins directory ---------------------------------
install -d -o root -g glasssvc -m 0750 /opt/glassboard/plugins
cat > /opt/glassboard/plugins/README.txt <<'EOF'
Drop-in plugins for the GlassBoard dashboard ("hot reload" support feature).

Any *.py file here is loaded by the running app within 60 seconds;
define a Flask Blueprint named `bp` and its routes go live. Provided
per the vendor support contract; do not remove.
EOF
chown root:glasssvc /opt/glassboard/plugins/README.txt

# -- systemd unit ---------------------------------------------------------------
cat > /root/rosemoor-prep/glassboard-app.service <<'EOF'
[Unit]
Description=GlassBoard dashboard (Rosemoor glasshouse)
After=network.target mariadb.service redis-server.service

[Service]
Type=simple
WorkingDirectory=/opt/glassboard
ExecStart=/usr/bin/python3 /opt/glassboard/app.py
Restart=on-failure
User=glasssvc
Group=glasssvc

[Install]
WantedBy=multi-user.target
EOF
install -m 0644 /root/rosemoor-prep/glassboard-app.service /etc/systemd/system/glassboard-app.service
systemctl daemon-reload
systemctl enable --now glassboard-app.service

# -- smoke test -------------------------------------------------------------------
sleep 2
curl -fsS http://127.0.0.1:8080/ >/dev/null
echo "prep04: GlassBoard serving on :8080; recent app journal:"
journalctl -u glassboard-app -n 3 --no-pager || true
