<?php
declare(strict_types=1);

final class OtpRateLimiter
{
    public function __construct(private readonly string $filePath)
    {
        $directory = dirname($this->filePath);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to create rate-limit storage directory.');
        }
    }

    public function allow(string $email, string $ip, int $now): bool
    {
        $handle = fopen($this->filePath, 'c+');
        if ($handle === false) {
            throw new RuntimeException('Unable to open rate-limit storage.');
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Unable to lock rate-limit storage.');
            }

            rewind($handle);
            $contents = stream_get_contents($handle);
            $data = $contents === '' ? [] : json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($data)) {
                throw new RuntimeException('Rate-limit storage has an invalid format.');
            }

            $emailKey = hash('sha256', $email);
            $ipKey = hash('sha256', $ip);
            $emailRequests = array_values(array_filter(
                $data['email'][$emailKey] ?? [],
                static fn (int $time): bool => $time > $now - 3600,
            ));
            $ipRequests = array_values(array_filter(
                $data['ip'][$ipKey] ?? [],
                static fn (int $time): bool => $time > $now - 3600,
            ));

            $allowed = !(count($emailRequests) >= 3
                || (count($emailRequests) > 0 && end($emailRequests) > $now - 60)
                || count($ipRequests) >= 10);

            if ($allowed) {
                $emailRequests[] = $now;
                $ipRequests[] = $now;
            }

            $data['email'] = array_filter($data['email'] ?? [], static fn (array $times): bool => count($times) > 0);
            $data['ip'] = array_filter($data['ip'] ?? [], static fn (array $times): bool => count($times) > 0);
            if ($emailRequests === []) {
                unset($data['email'][$emailKey]);
            } else {
                $data['email'][$emailKey] = $emailRequests;
            }
            if ($ipRequests === []) {
                unset($data['ip'][$ipKey]);
            } else {
                $data['ip'][$ipKey] = $ipRequests;
            }

            rewind($handle);
            if (!ftruncate($handle, 0)) {
                throw new RuntimeException('Unable to update rate-limit storage.');
            }
            $encoded = json_encode($data, JSON_THROW_ON_ERROR);
            if (fwrite($handle, $encoded) !== strlen($encoded) || !fflush($handle)) {
                throw new RuntimeException('Unable to write rate-limit storage.');
            }

            return $allowed;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
