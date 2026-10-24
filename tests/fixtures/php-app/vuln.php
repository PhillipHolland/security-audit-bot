<?php
// Fictional fixture for rule tests. Not real code.
$prefs = unserialize($_COOKIE['prefs']);
$safe = unserialize($_COOKIE['prefs'], ['allowed_classes' => false]);
eval($_GET['code']);
include $_GET['page'] . '.php';
require_once 'config.php';
$rows = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
$ok = mysqli_query($conn, "SELECT * FROM users WHERE id = " . intval($_GET['id']));
$users = DB::select("SELECT * FROM users WHERE name = '" . $name . "'");
phpinfo();
