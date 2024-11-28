<?php

namespace DomainChecker;

class Logger {
    private $logFile;
    private $logDir;

    public function __construct($logDir = null) {
        $this->logDir = $logDir ?? __DIR__ . '/../logs';
        if (!is_dir($this->logDir)) {
            mkdir($this->logDir, 0755, true);
        }
        $this->logFile = $this->logDir . '/domain_checks.log';
    }

    public function logCheck($domain, $results = null) {
        $timestamp = date('Y-m-d H:i:s');
        $ip = $this->getClientIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $referer = $_SERVER['HTTP_REFERER'] ?? 'Direct';
        $requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'Unknown';
        $requestUri = $_SERVER['REQUEST_URI'] ?? 'Unknown';
        $language = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'Unknown';

        $logEntry = [
            'timestamp' => $timestamp,
            'ip' => $ip,
            'domain' => $domain,
            'user_agent' => $userAgent,
            'referer' => $referer,
            'request_method' => $requestMethod,
            'request_uri' => $requestUri,
            'language' => $language,
            'results' => $results
        ];

        // Convert to JSON for storage
        $logLine = json_encode($logEntry) . "\n";
        
        // Write to log file
        file_put_contents($this->logFile, $logLine, FILE_APPEND | LOCK_EX);

        // Rotate log if needed
        $this->rotateLogIfNeeded();
    }

    private function getClientIP() {
        $headers = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_REAL_IP',       // Nginx proxy
            'HTTP_X_FORWARDED_FOR', // Common proxy header
            'REMOTE_ADDR'           // Direct connection
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                if (strpos($ip, ',') !== false) {
                    // If multiple IPs, take the first one
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                return $ip;
            }
        }

        return 'Unknown';
    }

    private function rotateLogIfNeeded() {
        if (!file_exists($this->logFile)) {
            return;
        }

        $maxSize = 10 * 1024 * 1024; // 10MB
        if (filesize($this->logFile) > $maxSize) {
            $timestamp = date('Y-m-d_H-i-s');
            $newFile = $this->logDir . '/domain_checks_' . $timestamp . '.log';
            rename($this->logFile, $newFile);
            
            // Compress old log
            if (file_exists($newFile)) {
                $gz = gzopen($newFile . '.gz', 'w9');
                gzwrite($gz, file_get_contents($newFile));
                gzclose($gz);
                unlink($newFile);
            }
        }
    }

    public function getRecentChecks($limit = 100) {
        if (!file_exists($this->logFile)) {
            return [];
        }

        $checks = [];
        $lines = file($this->logFile);
        $lines = array_reverse($lines); // Most recent first

        foreach ($lines as $line) {
            if (count($checks) >= $limit) break;
            $check = json_decode(trim($line), true);
            if ($check) {
                $checks[] = $check;
            }
        }

        return $checks;
    }
}
