<?php
    class DomainChecker {
        private $config;
        private $debug = [];
        
        public function __construct($config) {
            $this->config = $config;
        }

        // ... [Previous methods remain the same until checkDnssec] ...

        private function checkDnssec($domain) {
            try {
                $this->addDebug('DNSSEC', 'Starting DNSSEC check for: ' . $domain);

                // First check for DNSKEY records
                $dnskey_records = @dns_get_record($domain, DNS_ANY);
                $this->addDebug('DNSSEC', 'Checking DNSKEY records', $dnskey_records);

                // Check parent zone for DS records
                $parts = explode('.', $domain);
                if (count($parts) > 1) {
                    array_shift($parts);
                    $parent = implode('.', $parts);
                    $ds_check = @dns_get_record($domain, DNS_ANY);
                    $this->addDebug('DNSSEC', 'Checking DS records in parent zone', $ds_check);
                }

                // Look for specific DNSSEC indicators
                foreach ($dnskey_records as $record) {
                    if (isset($record['type'])) {
                        $type = strtoupper($record['type']);
                        if ($type === 'DNSKEY' || $type === 'RRSIG' || $type === 'NSEC' || $type === 'NSEC3' || $type === 'DS') {
                            return [
                                'status' => 'good',
                                'message' => 'DNSSEC is enabled',
                                'record' => "Found $type record"
                            ];
                        }
                    }
                }

                // Check SOA record for RRSIG
                $soa_records = @dns_get_record($domain, DNS_SOA);
                foreach ($soa_records as $record) {
                    if (isset($record['rrsig'])) {
                        return [
                            'status' => 'good',
                            'message' => 'DNSSEC is enabled (RRSIG found)',
                            'record' => 'Found RRSIG in SOA record'
                        ];
                    }
                }

                // Additional check for TXT records that might indicate DNSSEC
                $txt_records = @dns_get_record($domain, DNS_TXT);
                foreach ($txt_records as $record) {
                    if (isset($record['txt']) && 
                        (stripos($record['txt'], 'dnssec') !== false || 
                         stripos($record['txt'], 'signed') !== false)) {
                        return [
                            'status' => 'good',
                            'message' => 'DNSSEC is enabled',
                            'record' => $record['txt']
                        ];
                    }
                }

                // Try to detect DNSSEC by checking for common patterns in the response
                if (!empty($dnskey_records)) {
                    foreach ($dnskey_records as $record) {
                        if (isset($record['entries']) && is_array($record['entries'])) {
                            foreach ($record['entries'] as $entry) {
                                if (strpos($entry, 'DNSKEY') !== false || 
                                    strpos($entry, 'RRSIG') !== false) {
                                    return [
                                        'status' => 'good',
                                        'message' => 'DNSSEC is enabled',
                                        'record' => $entry
                                    ];
                                }
                            }
                        }
                    }
                }

                return ['status' => 'bad', 'message' => 'DNSSEC not detected'];
            } catch (Exception $e) {
                $this->addDebug('DNSSEC', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkDane($domain) {
            try {
                $this->addDebug('DANE', 'Starting DANE check for: ' . $domain);

                // Get MX records first
                $mx_records = dns_get_record($domain, DNS_MX);
                $this->addDebug('DANE', 'Found MX records', $mx_records);

                if (!empty($mx_records)) {
                    foreach ($mx_records as $mx) {
                        $mx_host = rtrim($mx['target'], '.');
                        $this->addDebug('DANE', 'Checking MX host: ' . $mx_host);

                        // Try direct TLSA lookup
                        $tlsa_query = '_25._tcp.' . $mx_host;
                        $records = @dns_get_record($tlsa_query, DNS_ANY);
                        $this->addDebug('DANE', 'Checking TLSA records for: ' . $tlsa_query, $records);

                        // Check if we got a real TLSA record
                        foreach ($records as $record) {
                            if (isset($record['type'])) {
                                $type = strtoupper($record['type']);
                                if ($type === 'TLSA' || $type === '52') {
                                    return [
                                        'status' => 'good',
                                        'message' => 'DANE is properly configured for ' . $mx_host,
                                        'record' => 'Found TLSA record'
                                    ];
                                }
                            }
                        }

                        // Check other common ports
                        foreach (['465', '587'] as $port) {
                            $tlsa_query = '_' . $port . '._tcp.' . $mx_host;
                            $records = @dns_get_record($tlsa_query, DNS_ANY);
                            $this->addDebug('DANE', "Checking TLSA records for port $port: " . $tlsa_query, $records);

                            foreach ($records as $record) {
                                if (isset($record['type'])) {
                                    $type = strtoupper($record['type']);
                                    if ($type === 'TLSA' || $type === '52') {
                                        return [
                                            'status' => 'good',
                                            'message' => "DANE is properly configured for port $port on " . $mx_host,
                                            'record' => 'Found TLSA record'
                                        ];
                                    }
                                }
                            }
                        }
                    }
                }

                // Check the domain itself as a fallback
                $tlsa_query = '_25._tcp.' . $domain;
                $records = @dns_get_record($tlsa_query, DNS_ANY);
                $this->addDebug('DANE', 'Checking TLSA records for domain: ' . $tlsa_query, $records);

                foreach ($records as $record) {
                    if (isset($record['type'])) {
                        $type = strtoupper($record['type']);
                        if ($type === 'TLSA' || $type === '52') {
                            return [
                                'status' => 'good',
                                'message' => 'DANE is enabled for domain',
                                'record' => 'Found TLSA record'
                            ];
                        }
                    }
                }

                return ['status' => 'bad', 'message' => 'No DANE records found'];
            } catch (Exception $e) {
                $this->addDebug('DANE', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        // ... [Rest of the methods remain exactly the same] ...

    }
    ?>
