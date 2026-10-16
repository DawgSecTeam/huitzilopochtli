#!/bin/sh
# Lantern Hill prep 04/05 -- the catalog app: deploy, systemd unit, apache
# reverse proxy. The app logs every request to stdout -> journald under
# `library-app.service`, which is what makes `journalctl -u library-app` a
# primary IR source on this box.
set -eu

# -- app directory (root-owned, group-readable by the service account) --------
install -d -o root -g catalogsvc -m 0750 /opt/library
install -o root -g catalogsvc -m 0640 /root/lantern-prep/app.py /opt/library/app.py
install -o root -g catalogsvc -m 0640 /root/lantern-prep/library.env /opt/library/.env

# -- the vendor "hot-reload" plugins directory ---------------------------------
install -d -o root -g catalogsvc -m 0755 /opt/library/plugins
cat > /opt/library/plugins/README.txt <<'EOF'
Drop-in plugins for the catalog app ("hot reload" support feature).

Any *.py file here is loaded by the running app within 60 seconds;
define a Flask Blueprint named `bp` and its routes go live. Provided
per the vendor support contract; do not remove.
EOF
chown root:catalogsvc /opt/library/plugins/README.txt

# -- systemd unit ---------------------------------------------------------------
install -m 0644 /root/lantern-prep/library-app.service /etc/systemd/system/library-app.service
systemctl daemon-reload
systemctl enable --now library-app.service

# -- apache in front on :80 ------------------------------------------------------
install -m 0644 /root/lantern-prep/library.conf /etc/apache2/sites-available/library.conf
a2enmod -q proxy proxy_http
a2dissite -q 000-default || true
a2ensite -q library
apachectl configtest
systemctl restart apache2

# -- smoke test -------------------------------------------------------------------
sleep 2
curl -fsS http://127.0.0.1/ >/dev/null
echo "prep04: catalog serving on :80; recent app journal:"
journalctl -u library-app -n 3 --no-pager || true
