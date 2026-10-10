<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/OtpRateLimiter.php';
require_once __DIR__ . '/../src/SmtpMailer.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function respond(int $status, array $body): never
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    respond(405, ['error' => 'Use POST for this endpoint.']);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($path !== '/api/otp/generate') {
    respond(404, ['error' => 'Endpoint not found.']);
}

$config = require __DIR__ . '/../config.php';
if (!is_array($config)) {
    respond(500, ['error' => 'Server configuration is invalid.']);
}

$expectedKey = $config['api_key'] ?? '';
$providedAuthorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (!is_string($expectedKey)
    || strlen($expectedKey) < 32
    || $expectedKey === 'REPLACE_WITH_A_RANDOM_SECRET_API_KEY'
    || !is_string($providedAuthorization)
    || !str_starts_with($providedAuthorization, 'Bearer ')
    || !hash_equals($expectedKey, substr($providedAuthorization, 7))) {
    respond(401, ['error' => 'Unauthorized. Provide a valid Bearer API key.']);
}

$contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($contentLength > 4096) {
    respond(413, ['error' => 'Request body is too large.']);
}

$rawBody = file_get_contents('php://input');
try {
    $body = json_decode($rawBody === false ? '' : $rawBody, true, 32, JSON_THROW_ON_ERROR);
} catch (JsonException) {
    respond(400, ['error' => 'Request body must be valid JSON.']);
}
if (!is_array($body)) {
    respond(400, ['error' => 'Request body must be a JSON object.']);
}

$email = $body['email'] ?? null;
if (!is_string($email) || filter_var(trim($email), FILTER_VALIDATE_EMAIL) === false) {
    respond(400, ['error' => 'Provide a valid recipient email in the email field.']);
}
$email = strtolower(trim($email));

$sender = $config['sender_email'] ?? '';
$password = $config['app_password'] ?? '';
$host = $config['smtp_host'] ?? 'smtp.gmail.com';
$port = $config['smtp_port'] ?? 587;
if (!is_string($sender)
    || filter_var($sender, FILTER_VALIDATE_EMAIL) === false
    || !is_string($password)
    || $password === ''
    || $password === 'PASTE_NEW_GMAIL_APP_PASSWORD_HERE'
    || !is_string($host)
    || !is_int($port)
    || $port < 1
    || $port > 65535) {
    respond(503, ['error' => 'Configure a sender Gmail address, App Password, SMTP host, and port in config.php.']);
}

try {
    $limiter = new OtpRateLimiter(__DIR__ . '/../storage/rate-limits.json');
    if (!$limiter->allow($email, $_SERVER['REMOTE_ADDR'] ?? 'unknown', time())) {
        respond(429, ['error' => 'OTP request limit reached. Wait before trying again.']);
    }

    $otp = sprintf('%06d', random_int(0, 999999));
    $mailer = new SmtpMailer($host, $port, $sender, preg_replace('/\s+/', '', $password));
    $mailer->send($email, 'Your verification code', "Your verification code is {$otp}. It expires in 5 minutes.");
} catch (Throwable $exception) {
    error_log($exception->getMessage());
    respond(502, ['error' => 'Email delivery failed. Check the sender credentials and SMTP configuration.']);
}

respond(200, [
    'success' => true,
    'email' => $email,
    'otp' => $otp,
    'expires_in' => 300,
]);
