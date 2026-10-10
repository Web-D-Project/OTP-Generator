<?php
declare(strict_types=1);

final class SmtpMailer
{
    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $username,
        private readonly string $password,
    ) {
    }

    public function send(string $recipient, string $subject, string $message): void
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('The PHP OpenSSL extension is required for secure SMTP.');
        }
        if (preg_match('/^[A-Za-z0-9.-]+$/', $this->host) !== 1) {
            throw new RuntimeException('SMTP host contains invalid characters.');
        }

        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'peer_name' => $this->host,
            ],
        ]);
        $socket = stream_socket_client(
            "tcp://{$this->host}:{$this->port}",
            $errorCode,
            $errorMessage,
            15,
            STREAM_CLIENT_CONNECT,
            $context,
        );
        if ($socket === false) {
            throw new RuntimeException("Unable to connect to SMTP server: {$errorMessage} ({$errorCode}).");
        }

        stream_set_timeout($socket, 15);

        try {
            $this->expect($socket, [220]);
            $this->command($socket, 'EHLO localhost', [250]);
            $this->command($socket, 'STARTTLS', [220]);

            if (stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT) !== true) {
                throw new RuntimeException('Unable to establish secure SMTP connection.');
            }

            $this->command($socket, 'EHLO localhost', [250]);
            $this->command($socket, 'AUTH LOGIN', [334]);
            $this->command($socket, base64_encode($this->username), [334]);
            $this->command($socket, base64_encode($this->password), [235]);
            $this->command($socket, "MAIL FROM:<{$this->username}>", [250]);
            $this->command($socket, "RCPT TO:<{$recipient}>", [250, 251]);
            $this->command($socket, 'DATA', [354]);

            $body = preg_replace("/\r\n|\r|\n/", "\r\n", $message);
            $body = preg_replace('/^\./m', '..', $body);
            $headers = [
                "From: {$this->username}",
                "To: {$recipient}",
                "Subject: {$subject}",
                'Date: ' . date(DATE_RFC2822),
                'MIME-Version: 1.0',
                'Content-Type: text/plain; charset=UTF-8',
                'Content-Transfer-Encoding: 8bit',
            ];
            $this->write($socket, implode("\r\n", $headers) . "\r\n\r\n" . $body . "\r\n.\r\n");
            $this->expect($socket, [250]);
            $this->command($socket, 'QUIT', [221]);
        } finally {
            fclose($socket);
        }
    }

    private function command($socket, string $command, array $expectedCodes): void
    {
        $this->write($socket, $command . "\r\n");
        $this->expect($socket, $expectedCodes);
    }

    private function write($socket, string $data): void
    {
        $length = strlen($data);
        $written = 0;
        while ($written < $length) {
            $result = fwrite($socket, substr($data, $written));
            if ($result === false || $result === 0) {
                throw new RuntimeException('Unable to write to SMTP server.');
            }
            $written += $result;
        }
    }

    private function expect($socket, array $expectedCodes): void
    {
        $response = '';
        do {
            $line = fgets($socket, 515);
            if ($line === false) {
                $meta = stream_get_meta_data($socket);
                $reason = $meta['timed_out'] ? 'timed out' : 'connection closed';
                throw new RuntimeException("SMTP server {$reason} before responding.");
            }
            $response .= $line;
        } while (strlen($line) >= 4 && $line[3] === '-');

        $code = (int) substr($response, 0, 3);
        if (!in_array($code, $expectedCodes, true)) {
            throw new RuntimeException('SMTP server rejected the request with response: ' . trim($response));
        }
    }
}
