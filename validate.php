<?php

function validateDomain($domain) {
    try {
        // Check for DNSSEC using PHP's native DNS functions
        $records = @dns_get_record($domain, DNS_A);
        if (!empty($records)) {
            foreach ($records as $record) {
                if (isset($record['type']) && $record['type'] === 'RRSIG') {
                    return true;
                }
            }
        }

        $ns_records = @dns_get_record($domain, DNS_NS);
        if (!empty($ns_records)) {
            foreach ($ns_records as $record) {
                if (isset($record['type']) && $record['type'] === 'RRSIG') {
                    return true;
                }
            }
        }

        $soa_records = @dns_get_record($domain, DNS_SOA);
        if (!empty($soa_records)) {
            foreach ($soa_records as $record) {
                if (isset($record['type']) && $record['type'] === 'RRSIG') {
                    return true;
                }
            }
        }

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
        return false;
    }

    return false;
}