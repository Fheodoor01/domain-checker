<?php
    class DomainChecker {
        private $config;
        
        public function __construct($config) {
            $this->config = $config;
        }
        
        public function checkAll($domain) {
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

            return $results;
        }

        private function calculateScore($results) {
            $weights = [
                'nameservers' => 0.5,
                'smtp' => 0.5,
                'dnssec' => 0.5,
                'spf' => 0.75,
                'dmarc' => 0.75,
                'dane' => 0.25,
                'tls' => 0.5,
                'tls_report' => 0.25,
                'mta_sts' => 0.25,
                'bimi' => 0.25
            ];

            $score = 0;
            $totalWeight = 0;

            foreach ($weights as $check => $weight) {
                if (isset($results[$check]['status'])) {
                    $totalWeight += $weight;
                    if ($results[$check]['status'] === 'good') {
                        $score += $weight;
                    }
                }
            }

            return number_format(($score / $totalWeight) * 5, 2);
        }

        private function checkNameServers($domain) {
            try {
                $records = dns_get_record($domain, DNS_NS);
                if (count($records) >= 2) {
                    return [
                        'status' => 'good',
                        'message' => 'Found ' . count($records) . ' name servers',
                        'records' => array_map(function($r) { return $r['target']; }, $records)
                    ];
                } else if (count($records) === 1) {
                    return [
                        'status' => 'warning',
                        'message' => 'Only one name server found. Multiple name servers are recommended.',
                        'records' => array_map(function($r) { return $r['target']; }, $records)
                    ];
                }
                return ['status' => 'bad', 'message' => 'No name servers found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkSMTP($domain) {
            try {
                $mxRecords = dns_get_record($domain, DNS_MX);
                if (!empty($mxRecords)) {
                    return [
                        'status' => 'good',
                        'message' => 'Found ' . count($mxRecords) . ' SMTP servers',
                        'records' => array_map(function($r) { 
                            return ['host' => $r['target'], 'priority' => $r['pri']]; 
                        }, $mxRecords)
                    ];
                }
                return ['status' => 'bad', 'message' => 'No SMTP servers found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkDNSSEC($domain) {
            try {
                // First try SOA record with RRSIG
                $soa_records = dns_get_record($domain, DNS_SOA);
                if (!empty($soa_records)) {
                    foreach ($soa_records as $record) {
                        if (isset($record['rrsig'])) {
                            return [
                                'status' => 'good',
                                'message' => 'DNSSEC is properly configured',
                                'record' => 'Found RRSIG for SOA record'
                            ];
                        }
                    }
                }

                // Try ANY query to catch all possible DNSSEC records
                $records = dns_get_record($domain, DNS_ANY);
                foreach ($records as $record) {
                    if (isset($record['type'])) {
                        // Check for any DNSSEC-related record types
                        if (in_array($record['type'], ['DNSKEY', 'RRSIG', 'DS', 'NSEC', 'NSEC3'])) {
                            return [
                                'status' => 'good',
                                'message' => 'DNSSEC is enabled',
                                'record' => 'Found ' . $record['type'] . ' record'
                            ];
                        }
                    }
                }

                // Additional check for specific TXT record that some registrars use
                $txt_records = dns_get_record($domain, DNS_TXT);
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

                return ['status' => 'bad', 'message' => 'DNSSEC not detected'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkSPF($domain) {
            try {
                $records = dns_get_record($domain, DNS_TXT);
                foreach ($records as $record) {
                    if (isset($record['txt']) && strpos($record['txt'], 'v=spf1') === 0) {
                        $strength = $this->analyzeSPFStrength($record['txt']);
                        return [
                            'status' => 'good',
                            'message' => 'SPF record found',
                            'strength' => $strength,
                            'record' => $record['txt']
                        ];
                    }
                }
                return ['status' => 'bad', 'message' => 'No SPF record found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function analyzeSPFStrength($record) {
            if (strpos($record, '-all') !== false) {
                return 'strong';
            } else if (strpos($record, '~all') !== false) {
                return 'medium';
            }
            return 'weak';
        }

        private function checkDMARC($domain) {
            try {
                $records = dns_get_record('_dmarc.' . $domain, DNS_TXT);
                foreach ($records as $record) {
                    if (isset($record['txt']) && strpos($record['txt'], 'v=DMARC1') === 0) {
                        $strength = $this->analyzeDMARCStrength($record['txt']);
                        return [
                            'status' => 'good',
                            'message' => 'DMARC record found',
                            'strength' => $strength,
                            'record' => $record['txt']
                        ];
                    }
                }
                return ['status' => 'bad', 'message' => 'No DMARC record found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function analyzeDMARCStrength($record) {
            if (strpos($record, 'p=reject') !== false) {
                return 'strong';
            } else if (strpos($record, 'p=quarantine') !== false) {
                return 'medium';
            }
            return 'weak';
        }

        private function checkDANE($domain) {
            try {
                // Get MX records first
                $mx_records = dns_get_record($domain, DNS_MX);
                if (!empty($mx_records)) {
                    foreach ($mx_records as $mx) {
                        $mx_host = rtrim($mx['target'], '.');
                        
                        // Check common DANE record locations
                        $check_locations = [
                            '_25._tcp.',
                            '_465._tcp.',
                            '_587._tcp.',
                            '_submission._tcp.',
                            '_submissions._tcp.'
                        ];

                        foreach ($check_locations as $prefix) {
                            // Check both the MX host and the original domain
                            $hosts_to_check = [$mx_host, $domain];
                            
                            foreach ($hosts_to_check as $host) {
                                $records = dns_get_record($prefix . $host, DNS_ANY);
                                foreach ($records as $record) {
                                    if (isset($record['type']) && 
                                        (strtoupper($record['type']) === 'TLSA' || 
                                         strpos($record['type'], '52') !== false)) { // 52 is the numeric type for TLSA
                                        return [
                                            'status' => 'good',
                                            'message' => 'DANE is properly configured for ' . $host,
                                            'record' => 'Found TLSA record at ' . $prefix . $host
                                        ];
                                    }
                                }
                            }
                        }
                    }
                }

                // Direct domain check without MX
                foreach (['_25._tcp.', '_465._tcp.', '_587._tcp.'] as $prefix) {
                    $records = dns_get_record($prefix . $domain, DNS_ANY);
                    foreach ($records as $record) {
                        if (isset($record['type']) && 
                            (strtoupper($record['type']) === 'TLSA' || 
                             strpos($record['type'], '52') !== false)) {
                            return [
                                'status' => 'good',
                                'message' => 'DANE is enabled for domain',
                                'record' => 'Found TLSA record at ' . $prefix . $domain
                            ];
                        }
                    }
                }

                return ['status' => 'bad', 'message' => 'No DANE records found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkTLS($domain) {
            try {
                $mxRecords = dns_get_record($domain, DNS_MX);
                if (!empty($mxRecords)) {
                    return [
                        'status' => 'good',
                        'message' => 'MX records found, TLS support assumed'
                    ];
                }
                return ['status' => 'bad', 'message' => 'No MX records found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkTLSReport($domain) {
            try {
                $records = dns_get_record('_smtp._tls.' . $domain, DNS_TXT);
                foreach ($records as $record) {
                    if (isset($record['txt']) && strpos($record['txt'], 'v=TLSRPTv1') === 0) {
                        return [
                            'status' => 'good',
                            'message' => 'TLS reporting enabled',
                            'record' => $record['txt']
                        ];
                    }
                }
                return ['status' => 'bad', 'message' => 'TLS reporting not enabled'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkMTASTS($domain) {
            try {
                $records = dns_get_record('_mta-sts.' . $domain, DNS_TXT);
                foreach ($records as $record) {
                    if (isset($record['txt']) && strpos($record['txt'], 'v=STSv1') === 0) {
                        return [
                            'status' => 'good',
                            'message' => 'MTA-STS enabled',
                            'record' => $record['txt']
                        ];
                    }
                }
                return ['status' => 'bad', 'message' => 'MTA-STS not enabled'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkBIMI($domain) {
            try {
                $records = dns_get_record('default._bimi.' . $domain, DNS_TXT);
                if (!empty($records)) {
                    foreach ($records as $record) {
                        if (isset($record['txt']) && strpos($record['txt'], 'v=BIMI1') === 0) {
                            return [
                                'status' => 'good',
                                'message' => 'BIMI record found',
                                'record' => $record['txt']
                            ];
                        }
                    }
                }
                return ['status' => 'bad', 'message' => 'No BIMI record found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }
    }
    ?>
