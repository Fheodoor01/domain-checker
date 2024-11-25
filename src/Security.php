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
        
        // Prepare descriptors for proc_open
        $descriptors = [
            0 => ['pipe', 'r'],  // stdin
            1 => ['pipe', 'w'],  // stdout
            2 => ['pipe', 'w']   // stderr
        ];
        
        // Start process
        $process = proc_open($full_command, $descriptors, $pipes);
        
        if (!is_resource($process)) {
            throw new \RuntimeException("Failed to execute command");
        }
        
        // Set non-blocking mode
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        
        // Initialize variables
        $output = '';
        $error = '';
        $start_time = time();
        
        // Read output with timeout
        while (true) {
            $read = [$pipes[1], $pipes[2]];
            $write = null;
            $except = null;
            
            // Check if process has timed out
            if (time() - $start_time > $timeout) {
                proc_terminate($process);
                throw new \RuntimeException("Command execution timed out");
            }
            
            // Wait for output
            if (stream_select($read, $write, $except, 1) === false) {
                break;
            }
            
            // Read stdout
            if (in_array($pipes[1], $read)) {
                $output .= fread($pipes[1], 8192);
                if (strlen($output) > self::MAX_OUTPUT_SIZE) {
                    proc_terminate($process);
                    throw new \RuntimeException("Command output exceeded maximum size");
                }
            }
            
            // Read stderr
            if (in_array($pipes[2], $read)) {
                $error .= fread($pipes[2], 8192);
                if (strlen($error) > self::MAX_OUTPUT_SIZE) {
                    proc_terminate($process);
                    throw new \RuntimeException("Command error output exceeded maximum size");
                }
            }
            
            // Check if process has finished
            $status = proc_get_status($process);
            if (!$status['running']) {
                break;
            }
        }
        
        // Close pipes
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        
        // Close process
        $exit_code = proc_close($process);
        
        if ($exit_code !== 0) {
            throw new \RuntimeException("Command failed with exit code: " . $exit_code);
        }
        
        return [
            'output' => $output,
            'error' => $error
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
}
