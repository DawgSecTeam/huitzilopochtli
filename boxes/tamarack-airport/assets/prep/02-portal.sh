#!/bin/sh
# Tamarack Regional Airport template prep -- step 2: the portal & the feed.
# Runs BEFORE `boxbuilder plant`: builds the legit content the display
# server exists to serve. The leaked backup / .env / .git land in the same
# webroot later, from the catalog.
set -eu

# --- the departures & arrivals portal (served by nginx from the default
# site root; the nginx catalog row installs the server at plant time).
install -d -m 0755 /var/www/html
cat > /var/www/html/index.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tamarack Regional Airport &mdash; Flight Information</title>
<style>
  body { font-family: "DejaVu Sans Mono", monospace; background: #101418;
         color: #e8e3d5; margin: 0; padding: 2rem; }
  h1 { color: #f0b429; letter-spacing: .08em; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: .45rem .8rem; text-align: left; border-bottom: 1px solid #2a2f36; }
  th { color: #f0b429; text-transform: uppercase; font-size: .8rem; }
  .remarks { color: #7fb069; }
  footer { margin-top: 2rem; color: #6c757d; font-size: .75rem; }
</style>
</head>
<body>
<h1>TAMARACK REGIONAL AIRPORT</h1>
<p>Flight information display &mdash; live board feed.</p>
<table>
  <tr><th>Time</th><th>Flight</th><th>Destination</th><th>Gate</th><th>Status</th></tr>
  <tr><td>07:35</td><td>TQ 204</td><td>Central City</td><td>2</td><td class="remarks">On time</td></tr>
  <tr><td>09:10</td><td>TQ 311</td><td>Lakeside</td><td>1</td><td class="remarks">Boarding</td></tr>
  <tr><td>11:45</td><td>TQ 402</td><td>Harbor City</td><td>3</td><td class="remarks">Delayed 20 min</td></tr>
  <tr><td>14:05</td><td>TQ 517</td><td>North Junction</td><td>2</td><td class="remarks">On time</td></tr>
  <tr><td>17:30</td><td>TQ 618</td><td>Central City</td><td>1</td><td class="remarks">Check displays</td></tr>
</table>
<footer>
  Flight Information Display System (FIDS) &mdash; schedule data served from the
  flightinfo database. Display systems integration by Skylark Field Services.
</footer>
</body>
</html>
EOF

# --- the display feed directory (the world-writable finding lands here at
# plant time; the directory itself is a legitimate part of the stack).
install -d -m 0755 /srv/fids/feed
printf 'board-feed v3 snapshot 2026-11-02\n' > /srv/fids/feed/board-feed.txt
printf 'gate-2 layout rev 8\n' > /srv/fids/feed/gate-layout.txt
chown -R root:root /srv/fids

echo "02-portal: webroot + feed ready ($(ls /var/www/html | tr '\n' ' '))"
