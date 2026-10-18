#!/bin/sh
# Lantern Hill prep 03/05 -- database: schema + seed data + the general
# query log ("give the db logging"). The query log is one of the box's four
# IR evidence sources: every statement the app (and the attacker's cron/timer
# payloads) run lands in /var/log/mysql/general.log.
set -eu

systemctl enable --now mariadb

# -- schema, seed data, least-privilege app account ---------------------------
mariadb < /root/lantern-prep/schema.sql

# -- query logging, file output ------------------------------------------------
install -d -o mysql -g adm -m 0750 /var/log/mysql
touch /var/log/mysql/general.log
chown mysql:adm /var/log/mysql/general.log
chmod 0640 /var/log/mysql/general.log
install -m 0644 /root/lantern-prep/99-library-ir.cnf \
    /etc/mysql/mariadb.conf.d/99-library-ir.cnf
systemctl restart mariadb

# -- confirm the recorder is rolling -------------------------------------------
sleep 1
if [ "$(mariadb -N -e 'SELECT @@global.general_log')" != "1" ]; then
    echo "prep03: FATAL -- general log did not come on" >&2
    exit 1
fi
echo "prep03: library DB seeded; general query log ON -> /var/log/mysql/general.log"
