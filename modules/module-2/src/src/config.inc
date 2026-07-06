<?php

// Remediation (RT-01/RT-05): credentials are read from the container
// environment (RDS_ENDPOINT/DB_USERNAME as plain env vars, DB_PASSWORD
// injected by ECS from Secrets Manager) instead of being hardcoded here.
$server = getenv('RDS_ENDPOINT');
$user = getenv('DB_USERNAME');
$pass = getenv('DB_PASSWORD');
$database = "appdb";

$conn = mysqli_connect($server, $user, $pass, $database);

if (!$conn) {
    die("<script>alert('Connection Failed.')</script>");
}

// Shared upload validation helper (RT-04): used by every endpoint that
// accepts a file upload. Only a small image/document whitelist is allowed,
// validated against the real file content (finfo), not the client-supplied
// name or Content-Type, and a fresh random name is always generated so the
// caller's filename (and its extension) is never trusted.
function safe_upload_filename($tmpPath, $allowedExt = ['png', 'jpg', 'jpeg', 'pdf']) {
    $allowedMime = [
        'png'  => 'image/png',
        'jpg'  => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'pdf'  => 'application/pdf',
    ];
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $tmpPath);
    finfo_close($finfo);

    foreach ($allowedExt as $ext) {
        if (isset($allowedMime[$ext]) && $allowedMime[$ext] === $mime) {
            return bin2hex(random_bytes(16)) . "." . $ext;
        }
    }
    return false;
}

?>