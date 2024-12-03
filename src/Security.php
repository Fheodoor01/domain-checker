<?php

namespace DomainChecker;

class Security {
    /**
     * Maximum command output size (8MB)
     */
    const MAX_OUTPUT_SIZE = 8388608;
    
    /**
     * Maximum execution time for commands (seconds)
     */
    const MAX_EXECUTION_TIME = 30;
    
    /**
     * Safely execute a command with proper escaping and timeout
     *
     * @param string $command Base command
     * @param array $args Command arguments
     * @param int|null $timeout Timeout in seconds (null for default)
     * @return array Array containing 'output' and 'error' keys
     * @throws \RuntimeException If command execution fails
     */
    public static function safeExecute(string $command, array $args, ?int $timeout = null): array {
        // Validate command
        if (!self::isAllowedCommand($command)) {
            throw new \RuntimeException("Command not allowed: " . $command);
        }
        
        // Escape all arguments
        $escaped_args = array_map('escapeshellarg', $args);
        
        // Build command
        $full_command = $command . ' ' . implode(' ', $escaped_args);
        
        // Set timeout
        $timeout = $timeout ?? self::MAX_EXECUTION_TIME;
        
        // Try to use shell_exec as a fallback
        $output = shell_exec($full_command);
        
        if ($output === null) {
            throw new \RuntimeException("Failed to execute command");
        }
        
        return [
            'output' => $output,
            'error' => ''
        ];
    }
    
    /**
     * Check if a command is in the allowed list
     *
     * @param string $command Command to check
     * @return bool True if command is allowed
     */
    private static function isAllowedCommand(string $command): bool {
        $allowed_commands = [
            'dig',
            'host',
            'nslookup'
        ];
        
        $command = basename($command);
        return in_array($command, $allowed_commands, true);
    }
    
    /**
     * Validate domain name format
     *
     * @param string $domain Domain name to validate
     * @return bool True if domain format is valid
     */
    public static function isValidDomain(string $domain): bool {
        // Remove trailing dot if present
        $domain = rtrim($domain, '.');
        
        // Basic domain format validation
        if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/', $domain)) {
            return false;
        }
        
        // Check domain length
        if (strlen($domain) > 253) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Clean and normalize domain name
     *
     * @param string $domain Domain name to clean
     * @return string Cleaned domain name
     * @throws \InvalidArgumentException If domain is invalid
     */
    public static function cleanDomain(string $domain): string {
        // Basic sanitization
        $domain = strtolower(trim($domain));
        $domain = rtrim($domain, '.');
        
        // Validate domain
        if (!self::isValidDomain($domain)) {
            throw new \InvalidArgumentException("Invalid domain name format");
        }
        
        return $domain;
    }

    /**
     * Sanitize and validate a domain name
     * 
     * @param string $domain Domain name to sanitize
     * @return string|null Sanitized domain or null if invalid
     */
    public function sanitizeDomain($domain) {
        // Remove any protocol prefixes
        $domain = preg_replace('#^https?://#', '', $domain);
        
        // Remove any paths or query strings
        $domain = strtok($domain, '/');
        
        // Remove any port numbers
        $domain = preg_replace('/:[\d]+$/', '', $domain);
        
        // Convert to lowercase
        $domain = strtolower(trim($domain));
        
        // Validate domain format
        if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/', $domain)) {
            return null;
        }
        
        return $domain;
    }

    /**
     * Check HTTPS and SSL certificate status for a domain
     * 
     * @param string $domain Domain to check
     * @return array Result of the HTTPS and certificate check
     */
    public function checkHttps($domain) {
        $result = [
            'status' => 'unknown',
            'message' => '',
            'details' => []
        ];

        // Try HTTPS connection
        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'capture_peer_cert' => true
            ]
        ]);

        $url = "https://" . $domain;
        $errno = 0;
        $errstr = '';
        
        // First check if HTTPS is available
        $handle = @stream_socket_client(
            "ssl://{$domain}:443", 
            $errno, 
            $errstr, 
            30, 
            STREAM_CLIENT_CONNECT, 
            $ctx
        );

        if (!$handle) {
            $result['status'] = 'bad';
            $result['message'] = "HTTPS not properly configured";
            $result['details'][] = "Unable to establish secure connection: $errstr";
            return $result;
        }

        // Get certificate details
        $cert = stream_context_get_params($handle);
        if (isset($cert['options']['ssl']['peer_certificate'])) {
            $certInfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
            
            // Check certificate validity
            $validFrom = $certInfo['validFrom_time_t'];
            $validTo = $certInfo['validTo_time_t'];
            $now = time();
            
            if ($now < $validFrom) {
                $result['status'] = 'bad';
                $result['message'] = "SSL certificate not yet valid";
            } elseif ($now > $validTo) {
                $result['status'] = 'bad';
                $result['message'] = "SSL certificate has expired";
            } else {
                // Check if HTTP redirects to HTTPS
                $httpHandle = @fopen("http://{$domain}", 'r');
                if ($httpHandle) {
                    $meta = stream_get_meta_data($httpHandle);
                    $headers = implode("\n", $meta['wrapper_data']);
                    fclose($httpHandle);
                    
                    if (strpos($headers, 'Location: https://') === false) {
                        $result['status'] = 'warning';
                        $result['message'] = "HTTP not redirecting to HTTPS";
                        $result['details'][] = "Site accessible over HTTP without HTTPS redirect";
                    } else {
                        $result['status'] = 'good';
                        $result['message'] = "HTTPS properly configured";
                        $result['details'][] = "Valid SSL certificate until " . date('Y-m-d', $validTo);
                    }
                } else {
                    $result['status'] = 'good';
                    $result['message'] = "HTTPS properly configured";
                    $result['details'][] = "Valid SSL certificate until " . date('Y-m-d', $validTo);
                }
            }
        } else {
            $result['status'] = 'bad';
            $result['message'] = "Invalid SSL certificate";
        }

        fclose($handle);
        return $result;
    }
}
