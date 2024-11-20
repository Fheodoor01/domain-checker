<?php
    class DomainChecker {
        private $config;
        private $debug = [];
        
        public function __construct($config) {
            $this->config = $config;
        }
        
        public function checkAll($domain) {
            $this->debug = []; // Reset debug info
            
            $results = [
                'nameservers' => $this->checkNameServers($domain),
                'smtp' => $this->checkSMTP($domain),
                'dnssec' => $this->checkDNSSEC($domain),
                'spf' => $this->checkSPF($domain),
                'dmarc' => $this->checkDMARC($domain),
                'dane' => $this->checkDANE($domain),
                'tls' => $this->checkTLS($domain),
                'tls_report' => $this->checkTLSReport($domain),
                'mta_sts' => $this->checkMTASTS($domain),
                'bimi' => $this->checkBIMI($domain)
            ];

            $score = $this->calculateScore($results);
            $results['overall_score'] = $score;
            $results['debug'] = $this->debug; // Add debug info to results

            return $results;
        }

        private function addDebug($check, $message, $data = null) {
            $this->debug[] = [
                'check' => $check,
                'message' => $message,
                'data' => $data,
                'time' => date('H:i:s')
            ];
        }

        // ... [previous code for calculateScore and other checks remains the same until DNSSEC] ...

        private function checkDNSSEC($domain) {
            try {
                $this->addDebug('DNSSEC', 'Starting DNSSEC check for domain: ' . $domain);

                // Try ANY query first
                $records = dns_get_record($domain, DNS_ANY);
                $this->addDebug('DNSSEC', 'DNS_ANY records found', $records);

                foreach ($records as $record) {
                    if (isset($record['type'])) {
                        $this->addDebug('DNSSEC', 'Checking record type: ' . $record['type']);
                        
                        // Check for any DNSSEC-related record types
                        if (in_array(strtoupper($record['type']), ['DNSKEY', 'RRSIG', 'DS', 'NSEC', 'NSEC3'])) {
                            $this->addDebug('DNSSEC', 'Found DNSSEC record type: ' . $record['type']);
                            return [
                                'status' => 'good',
                                'message' => 'DNSSEC is enabled',
                                'record' => 'Found ' . $record['type'] . ' record'
                            ];
                        }
                    }
                }

                // Try specific TXT records
                $txt_records = dns_get_record($domain, DNS_TXT);
                $this->addDebug('DNSSEC', 'Checking TXT records', $txt_records);

                foreach ($txt_records as $record) {
                    if (isset($record['txt'])) {
                        $this->addDebug('DNSSEC', 'Checking TXT record: ' . $record['txt']);
                    }
                }

                // Try SOA records
                $soa_records = dns_get_record($domain, DNS_SOA);
                $this->addDebug('DNSSEC', 'Checking SOA records', $soa_records);

                foreach ($soa_records as $record) {
                    if (isset($record['rrsig'])) {
                        $this->addDebug('DNSSEC', 'Found RRSIG in SOA record');
                        return [
                            'status' => 'good',
                            'message' => 'DNSSEC is enabled (RRSIG found)',
                            'record' => 'Found RRSIG in SOA record'
                        ];
                    }
                }

                $this->addDebug('DNSSEC', 'No DNSSEC records found');
                return ['status' => 'bad', 'message' => 'DNSSEC not detected'];
            } catch (Exception $e) {
                $this->addDebug('DNSSEC', 'Error during check: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkDANE($domain) {
            try {
                $this->addDebug('DANE', 'Starting DANE check for domain: ' . $domain);

                // Get MX records first
                $mx_records = dns_get_record($domain, DNS_MX);
                $this->addDebug('DANE', 'Found MX records', $mx_records);

                if (!empty($mx_records)) {
                    foreach ($mx_records as $mx) {
                        $mx_host = rtrim($mx['target'], '.');
                        $this->addDebug('DANE', 'Checking MX host: ' . $mx_host);
                        
                        // Check common DANE record locations
                        $check_locations = [
                            '_25._tcp.',
                            '_465._tcp.',
                            '_587._tcp.',
                            '_submission._tcp.',
                            '_submissions._tcp.'
                        ];

                        foreach ($check_locations as $prefix) {
                            $check_domain = $prefix . $mx_host;
                            $this->addDebug('DANE', 'Checking location: ' . $check_domain);
                            
                            $records = dns_get_record($check_domain, DNS_ANY);
                            $this->addDebug('DANE', 'Records found for ' . $check_domain, $records);

                            foreach ($records as $record) {
                                if (isset($record['type'])) {
                                    $this->addDebug('DANE', 'Found record type: ' . $record['type']);
                                    if (strtoupper($record['type']) === 'TLSA' || 
                                        strpos($record['type'], '52') !== false) {
                                        return [
                                            'status' => 'good',
                                            'message' => 'DANE is properly configured for ' . $mx_host,
                                            'record' => 'Found TLSA record at ' . $check_domain
                                        ];
                                    }
                                }
                            }
                        }
                    }
                }

                // Direct domain checks
                foreach (['_25._tcp.', '_465._tcp.', '_587._tcp.'] as $prefix) {
                    $check_domain = $prefix . $domain;
                    $this->addDebug('DANE', 'Checking direct domain: ' . $check_domain);
                    
                    $records = dns_get_record($check_domain, DNS_ANY);
                    $this->addDebug('DANE', 'Records found for direct domain', $records);

                    foreach ($records as $record) {
                        if (isset($record['type'])) {
                            $this->addDebug('DANE', 'Found record type: ' . $record['type']);
                            if (strtoupper($record['type']) === 'TLSA' || 
                                strpos($record['type'], '52') !== false) {
                                return [
                                    'status' => 'good',
                                    'message' => 'DANE is enabled for domain',
                                    'record' => 'Found TLSA record at ' . $check_domain
                                ];
                            }
                        }
                    }
                }

                $this->addDebug('DANE', 'No DANE records found');
                return ['status' => 'bad', 'message' => 'No DANE records found'];
            } catch (Exception $e) {
                $this->addDebug('DANE', 'Error during check: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        // ... [rest of the original methods remain the same] ...

    }
    ?>
