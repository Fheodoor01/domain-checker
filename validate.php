<?php

function validateDomain($domain) {
    return checkDnssecWithPhp($domain);
}

function checkDnssecWithPhp($domain) {
    try {
        // Try DNS_A first as it's most commonly supported
        $records = @dns_get_record($domain, DNS_A);
        if (!empty($records)) {
            foreach ($records as $record) {
                if (isset($record['type']) && $record['type'] === 'RRSIG') {
                    return true;
                }
            }
        }

        // Try DNS_NS records
        $ns_records = @dns_get_record($domain, DNS_NS);
        if (!empty($ns_records)) {
            foreach ($ns_records as $record) {
                if (isset($record['type']) && $record['type'] === 'RRSIG') {
                    return true;
                }
            }
        }

        // Try DNS_SOA records
        $soa_records = @dns_get_record($domain, DNS_SOA);
        if (!empty($soa_records)) {
            foreach ($soa_records as $record) {
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
                    if (isset($record['type'])) {
                        $type = strtoupper($record['type']);
                        if ($type === 'RRSIG' || $type === 'DNSKEY' || $type === 'DS') {
                            return true;
                        }
                    }
                }
            }
        }

    } catch (Exception $e) {
        // If any errors occur, assume no DNSSEC
        return false;
    }

    return false;
}