<?php

// Remediation (RT-07): payslip/reimbursement documents (PII: SSN, bank
// account numbers) used to be served as static files directly under
// DOCUMENT_ROOT with no access control - the hex filename was the only
// protection, and it worked with no session at all. This gateway requires
// an authenticated session and verifies the requester owns the record (or
// is admin/superadmin) before streaming anything from outside the web root.

include_once 'config.inc';
session_start();

if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

$f = $_GET['f'] ?? '';

// Strict allow-list: "<type>/<32 hex chars>.<ext>" is the only shape
// safe_upload_filename()/uploads ever produce. Anything else is rejected
// outright - this also blocks path traversal (`../`, absolute paths, etc.)
if (!preg_match('#^(payslips|reimbursments)/([a-f0-9]{32}\.(?:png|jpg|jpeg|pdf))$#', $f, $m)) {
    http_response_code(400);
    die("Invalid file reference");
}
$type = $m[1];
$relative = $m[1] . "/" . $m[2];

$table = $type === "payslips" ? "payslips" : "reimbursments";
$stmt = $conn->prepare("SELECT id FROM `$table` WHERE file = ? LIMIT 1");
$stmt->bind_param("s", $relative);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();

if (!$row) {
    http_response_code(404);
    die("Not found");
}

$isOwner = isset($_SESSION['id']) && (string)$_SESSION['id'] === (string)$row['id'];
$isAdmin = isset($_SESSION['isadmin']) && in_array($_SESSION['isadmin'], [1, 2], true);

if (!$isOwner && !$isAdmin) {
    http_response_code(403);
    die("Forbidden");
}

$fullPath = "/var/www/documents/" . $relative;
if (!is_file($fullPath)) {
    http_response_code(404);
    die("Not found");
}

$mimeByExt = [
    'pdf'  => 'application/pdf',
    'png'  => 'image/png',
    'jpg'  => 'image/jpeg',
    'jpeg' => 'image/jpeg',
];
$ext = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));
header('Content-Type: ' . ($mimeByExt[$ext] ?? 'application/octet-stream'));
header('Content-Length: ' . filesize($fullPath));
header('X-Content-Type-Options: nosniff');
readfile($fullPath);
