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
        // Check for DNSKEY records
        $dnskey = @dns_get_record($domain, DNS_DNSKEY);
        if (!empty($dnskey)) {
            return true;
        }

        // Check for RRSIG records
        $types = [DNS_A, DNS_AAAA, DNS_NS, DNS_SOA, DNS_MX, DNS_TXT];
        foreach ($types as $type) {
            $records = @dns_get_record($domain, $type);
            if (!empty($records)) {
                foreach ($records as $record) {
                    if (isset($record['type']) && $record['type'] === 'RRSIG') {
                        return true;
                    }
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
        $tld = substr($domain, strpos($domain, '.') + 1);
        $command = sprintf('dig +noall +answer %s DS', escapeshellarg($domain));
        exec($command, $output, $return_var);

        if ($return_var === 0 && !empty($output)) {
            foreach ($output as $line) {
                if (strpos($line, 'DS') !== false) {
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