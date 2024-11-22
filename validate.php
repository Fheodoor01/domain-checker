<?php

function validateDomain($domain) {
    // First try PHP's dns_get_record
    $hasDnssec = checkDnssecWithPhp($domain);
    if ($hasDnssec !== null) {
        return $hasDnssec;
    }

    // Fallback to dig command if PHP method fails
    return checkDnssecWithDig($domain);
}

function checkDnssecWithPhp($domain) {
    try {
        // Check for RRSIG records with various record types
        // DNS_A = 1, DNS_NS = 2, DNS_SOA = 6, DNS_MX = 15, DNS_TXT = 16, DNS_AAAA = 28
        $types = [1, 2, 6, 15, 16, 28];
        
        foreach ($types as $type) {
            $records = @dns_get_record($domain, $type);
            if (!empty($records)) {
                foreach ($records as $record) {
                    // Look for RRSIG records
                    if (isset($record['type']) && $record['type'] === 'RRSIG') {
                        return true;
                    }
                    
                    // Also check if any record contains RRSIG information
                    foreach ($record as $value) {
                        if (is_string($value) && stripos($value, 'RRSIG') !== false) {
                            return true;
                        }
                    }
                }
            }
        }
        
        // Try getting ANY records (type 255) as a last resort
        $any_records = @dns_get_record($domain, 255);
        if (!empty($any_records)) {
            foreach ($any_records as $record) {
                if (isset($record['type']) && 
                    (strpos($record['type'], 'RRSIG') !== false || 
                     strpos($record['type'], 'DNSKEY') !== false || 
                     strpos($record['type'], 'DS') !== false)) {
                    return true;
                }
            }
        }
    } catch (Exception $e) {
        return null; // Let's try dig as fallback
    }
    
    return false;
}

function checkDnssecWithDig($domain) {
    try {
        // Use dig to check for DNSSEC
        $command = sprintf('dig +dnssec +noall +answer %s DNSKEY', escapeshellarg($domain));
        exec($command, $output, $return_var);

        if ($return_var === 0 && !empty($output)) {
            foreach ($output as $line) {
                if (strpos($line, 'DNSKEY') !== false || strpos($line, 'RRSIG') !== false) {
                    return true;
                }
            }
        }

        // Try checking for DS records at parent
        $command = sprintf('dig +noall +answer %s DS', escapeshellarg($domain));
        exec($command, $output, $return_var);

        if ($return_var === 0 && !empty($output)) {
            foreach ($output as $line) {
                if (strpos($line, 'DS') !== false) {
                    return true;
                }
            }
        }

        // As a last resort, check for RRSIG records
        $command = sprintf('dig +dnssec +noall +answer %s', escapeshellarg($domain));
        exec($command, $output, $return_var);

        if ($return_var === 0 && !empty($output)) {
            foreach ($output as $line) {
                if (strpos($line, 'RRSIG') !== false) {
                    return true;
                }
            }
        }
    } catch (Exception $e) {
        // If both methods fail, assume no DNSSEC
        return false;
    }

    return false;
}