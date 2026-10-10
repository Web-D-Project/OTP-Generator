# OTP email API

This PHP API generates a cryptographically random six-digit OTP, sends it to an email address provided by another backend, and returns the OTP in the JSON response to the authenticated calling backend.

## Configure

Edit `config.php`:

- `sender_email`: Gmail account used to send OTP messages
- `app_password`: Gmail App Password for that account (not the normal Google password)
- `api_key`: a random secret shared only with the calling backend; at least 32 characters

Use a newly generated App Password. Revoke any password that has been shared or exposed. `config.php` is ignored by Git; do not commit credentials.

Generate an API key in PowerShell:

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

## Run

Gmail SMTP requires internet access. Start the API on the host where the PHP service will run:

```powershell
php -S 127.0.0.1:8000 public/router.php
```

For another backend on a different host, bind PHP to an appropriate interface and put it behind HTTPS. Do not expose the built-in PHP development server directly to the internet; use a production web server with TLS.

## Endpoint

`POST /api/otp/generate`

Headers:

```http
Authorization: Bearer YOUR_SHARED_API_KEY
Content-Type: application/json
```

Request:

```json
{"email":"recipient@example.com"}
```

Successful response:

```json
{
  "success": true,
  "email": "recipient@example.com",
  "otp": "004217",
  "expires_in": 300
}
```

The OTP is sent to the email and returned to the trusted calling backend. Do not send this response to a browser or expose the OTP to an end user through an API response. The caller should deliver it to the user using its own verification flow.

### Example calling backend (PowerShell)

```powershell
$headers = @{ Authorization = "Bearer YOUR_SHARED_API_KEY" }
$body = @{ email = "recipient@example.com" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri "https://your-otp-api.example.com/api/otp/generate" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body $body
```

Requests are limited to one per recipient per minute, three per recipient per hour, and ten per source IP per hour. The rate-limit state is stored under `storage/`, outside the public directory.
