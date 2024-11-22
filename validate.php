<?php

function validateDomain($domain) {
    // Try dig command first as it's more reliable for DNSSEC
    $hasDnssec = checkDnssecWithDig($domain);
    if ($hasDnssec) {
        return true;
    }

    // Fallback to PHP method if dig fails
    return checkDnssecWithPhp($domain);
}

function checkDnssecWithPhp($domain) {
    try {
        // Only use DNS_A type as it's guaranteed to exist
        $records = @dns_get_record($domain, DNS_A);
        if (!empty($records)) {
            foreach ($records as $record) {
                if (isset($record['type']) && $record['type'] === 'RRSIG') {
                    return true;
                }
            }
        }
        
        // Try DNS_ANY if available
        if (defined('DNS_ANY')) {
            $any_records = @dns_get_record($domain, DNS_ANY);
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
        }
    } catch (Exception $e) {
        // If PHP method fails, we already tried dig
        return false;
    }
    
    return false;
}

function checkDnssecWithDig($domain) {
    try {
        // First, check for DNSKEY records
        $command = sprintf('dig +dnssec +noall +answer %s DNSKEY', escapeshellarg($domain));
        exec($command, $output, $return_var);

        if ($return_var === 0 && !empty($output)) {
            foreach ($output as $line) {
                if (strpos($line, 'DNSKEY') !== false || strpos($line, 'RRSIG') !== false) {
                    return true;
                }
            }
        }

        // Then check for DS records
        $command = sprintf('dig +noall +answer %s DS', escapeshellarg($domain));
        exec($command, $output, $return_var);

        if ($return_var === 0 && !empty($output)) {
            foreach ($output as $line) {
                if (strpos($line, 'DS') !== false) {
                    return true;
                }
            }
        }

        // Finally, check for RRSIG records
        $command = sprintf('dig +dnssec +noall +answer %s SOA', escapeshellarg($domain));
        exec($command, $output, $return_var);

        if ($return_var === 0 && !empty($output)) {
            foreach ($output as $line) {
                if (strpos($line, 'RRSIG') !== false) {
                    return true;
                }
            }
        }
    } catch (Exception $e) {
        return false;
    }

    return false;
}