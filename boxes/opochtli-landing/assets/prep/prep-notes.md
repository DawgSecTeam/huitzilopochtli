# Template prep artifacts (Debian 13 CLI box)

What TEMPLATE PREP bakes in before any nakon plant (see box.yaml header for
the full list). These files are deployed, not scored — they are the box's
legitimate service stack.

- `index.php` — the Cargo Manifest Lookup app, deployed to
  `/var/www/html/index.php` (replaces the default index.html). Reads manifest
  rows from the SHARED port-authority MariaDB at 192.168.100.10:3306
  (workshop-shared-mariadb, Proxmox vmid 147); renders the page shell with an
  error row when the DB is unreachable, so the web-app liveness probe and the
  DB reachability probe stay independent.
- `cargo.sql` — the shared DB's schema + themed data. Run ON
  workshop-shared-mariadb (not on practice boxes): creates db `portauthority`,
  user `portauthority`@`192.168.100.%` (SELECT only, password `manifest-db`),
  binds nothing itself — set `bind-address = 0.0.0.0` in
  `/etc/mysql/mariadb.conf.d/50-server.cnf` on the DB VM.

Prep apt list: iptables ncat nmap apache2 libapache2-mod-php php-mysql
(no mariadb-server). Debian 13 splits `ncat` out of `nmap` into its own
package; the bind-shell unit hardcodes /usr/bin/ncat.

Accounts after prep: `harbormaster` only (sudo, bash, ~/Desktop). The
debian13-lite template ships `sysadmin` (uid 1000) and `ubuntu` — REMOVE both
during prep; the agent picks the lowest-numbered real user for the forensics
file, and a leftover sysadmin steals it (the v1 round shipped this defect).
