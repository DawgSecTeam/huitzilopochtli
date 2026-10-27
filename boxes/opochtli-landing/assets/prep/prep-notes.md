# Template prep artifacts (Debian 13 CLI box)

What TEMPLATE PREP bakes in before any nakon plant. These files are deployed,
not scored — they are the box's legitimate service stack.

## Deployed (unscored) stack

- `index.php` — the Cargo Manifest Lookup app, deployed to
  `/var/www/html/index.php` (replaces the default index page). It reads the
  manifest rows from a shared port-authority MariaDB over TCP 3306 and renders
  the page shell with an error row when the database is unreachable, so the
  web-app liveness probe and the DB reachability probe stay independent.
- `cargo.sql` — the database's schema plus the themed manifest rows. Run it
  once, as root, on the database host (not on a scored practice box): it
  creates the `portauthority` database and the SELECT-only `portauthority`
  account. The database listener must accept connections from the
  practice-network subnet.

## Packages

Prep apt list: iptables ncat nmap apache2 libapache2-mod-php php-mysql
(no mariadb-server on the box). Debian 13 splits `ncat` out of `nmap` into its
own package; the bind-shell unit hardcodes /usr/bin/ncat.

## Accounts

Accounts after prep: `harbormaster` only (sudo, bash, ~/Desktop). Delete any
stray base-image account during prep: the agent picks the lowest-numbered real
user for the forensics file, so a leftover low-uid user steals it.

## Values supplied at deploy time

Nothing environment-specific is committed; supply these at deploy time.

- **DB host** — `PORT_AUTHORITY_DB_HOST` in the web server's environment, or
  replace the `192.0.2.10` documentation placeholder in `index.php` (RFC 5737).
- **DB user / password** — `PORT_AUTHORITY_DB_USER` /
  `PORT_AUTHORITY_DB_PASSWORD` (defaults `portauthority` / `change-me`); the
  values must match the account `cargo.sql` created.
- **DB subnet grant** — replace `192.0.2.%` in `cargo.sql` with the
  practice-network subnet before running it, and set `bind-address` in
  `/etc/mysql/mariadb.conf.d/50-server.cnf` on the database host (for example
  `0.0.0.0` if every network must reach it).
- **Egress target** — the app's DB address must match the outbound-TCP-3306
  egress rule the scenario scores; keep the two consistent when substituting.
