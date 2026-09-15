<?php
// Opochtli Landing Port Authority — Cargo Manifest Lookup
// Backed by the shared port-authority MariaDB (workshop-shared-mariadb,
// 192.168.100.10:3306). If the database cannot be reached the page still
// renders; manifest rows just won't.
mysqli_report(MYSQLI_REPORT_OFF);
$db = mysqli_init();
$db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 2);
if (!$db->real_connect('192.168.100.10', 'portauthority', 'manifest-db', 'portauthority')) {
    $db = false;
}
header('Content-Type: text/html; charset=utf-8');
$q = isset($_GET['q']) ? trim((string)$_GET['q']) : '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cargo Manifest Lookup — Opochtli Landing Port Authority</title>
<style>
body{font-family:sans-serif;background:#eef4f6;color:#123;margin:2rem}
h1{color:#0E5A6D} table{border-collapse:collapse;background:#fff}
th,td{border:1px solid #b8ccd3;padding:.4rem .7rem}
th{background:#0E5A6D;color:#fff} form{margin:1rem 0}
.err{color:#8a1f1f;font-weight:bold}
</style>
</head>
<body>
<h1>Cargo Manifest Lookup</h1>
<p>Opochtli Landing Port Authority &mdash; duty pilot office. Restricted manifest data.</p>
<form method="get">
<input type="text" name="q" size="30" value="<?= htmlspecialchars($q, ENT_QUOTES) ?>" placeholder="vessel, cargo, or consignee">
<button type="submit">Search</button>
</form>
<?php if (!$db) { echo '<p class="err">database unavailable — manifest data cannot be retrieved</p>'; } else { ?>
<table>
<tr><th>Berth</th><th>Vessel</th><th>Cargo</th><th>Consignee</th><th>Status</th></tr>
<?php
$like = '%' . $q . '%';
$stmt = $db->prepare('SELECT berth, vessel, cargo, consignee, status FROM cargo_manifest WHERE vessel LIKE ? OR cargo LIKE ? OR consignee LIKE ? ORDER BY berth');
$stmt->bind_param('sss', $like, $like, $like);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
  echo '<tr><td>' . htmlspecialchars($row['berth']) . '</td><td>' . htmlspecialchars($row['vessel'])
     . '</td><td>' . htmlspecialchars($row['cargo']) . '</td><td>' . htmlspecialchars($row['consignee'])
     . '</td><td>' . htmlspecialchars($row['status']) . '</td></tr>';
}
if ($res->num_rows === 0) echo '<tr><td colspan="5">no matching manifest entries</td></tr>';
?>
</table>
<?php } ?>
</body>
</html>
