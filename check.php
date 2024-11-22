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
                'nameservers' => $this->checkNameservers($domain),
                'smtp' => $this->checkSmtp($domain),
                'dnssec' => $this->checkDnssec($domain),
                'spf' => $this->checkSpf($domain),
                'dmarc' => $this->checkDmarc($domain),
                'dane' => $this->checkDane($domain),
                'tls' => $this->checkTls($domain),
                'tls_report' => $this->checkTlsReport($domain),
                'mta_sts' => $this->checkMtaSts($domain),
                'bimi' => $this->checkBimi($domain)
            ];

            $score = $this->calculateScore($results);
            $results['overall_score'] = $score;
            $results['debug'] = $this->debug;

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

        private function checkNameservers($domain) {
            try {
                $this->addDebug('Nameservers', 'Checking nameservers for: ' . $domain);
                $records = dns_get_record($domain, DNS_NS);
                $this->addDebug('Nameservers', 'Found records', $records);

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
                $this->addDebug('Nameservers', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkSmtp($domain) {
            try {
                $this->addDebug('SMTP', 'Checking MX records for: ' . $domain);
                $mxRecords = dns_get_record($domain, DNS_MX);
                $this->addDebug('SMTP', 'Found records', $mxRecords);

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
                $this->addDebug('SMTP', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function executeDig($domain, $options) {
            $command = "dig " . $options . " " . escapeshellarg($domain);
            $output = [];
            $return_var = 0;
            exec($command, $output, $return_var);
            return ['output' => $output, 'status' => $return_var];
        }

        private function checkDnssec($domain) {
            try {
                $this->addDebug('DNSSEC', 'Starting DNSSEC check for: ' . $domain);
                
                // Get all records and log them in detail
                $records = @dns_get_record($domain, DNS_ALL);
                if ($records === false) {
                    $this->addDebug('DNSSEC', 'dns_get_record failed');
                    $records = [];
                }
                
                // Log each record type we find
                foreach ($records as $record) {
                    if (isset($record['type'])) {
                        $this->addDebug('DNSSEC', 'Found record type: ' . $record['type'], $record);
                    }
                }
                
                // Try different record type combinations
                $a_records = @dns_get_record($domain, DNS_A);
                $this->addDebug('DNSSEC', 'A records:', $a_records);
                
                $any_records = @dns_get_record($domain, DNS_ANY);
                $this->addDebug('DNSSEC', 'ANY records:', $any_records);
                
                $txt_records = @dns_get_record($domain, DNS_TXT);
                $this->addDebug('DNSSEC', 'TXT records:', $txt_records);
                
                // Combine all records for checking
                $all_records = array_merge(
                    $records,
                    $a_records ?: [],
                    $any_records ?: [],
                    $txt_records ?: []
                );
                
                $has_rrsig = false;
                $has_dnskey = false;
                $dnssec_records = [];
                
                foreach ($all_records as $record) {
                    if (!isset($record['type'])) continue;
                    
                    // Check for RRSIG in type field
                    if ($record['type'] === 'RRSIG') {
                        $has_rrsig = true;
                        $dnssec_records[] = $record;
                    }
                    // Check for DNSKEY in type field
                    else if ($record['type'] === 'DNSKEY') {
                        $has_dnskey = true;
                        $dnssec_records[] = $record;
                    }
                    // Also check if RRSIG appears in other fields (some PHP versions put it there)
                    else if (isset($record['rrsig']) || 
                            (isset($record['txt']) && strpos($record['txt'], 'RRSIG') !== false) ||
                            (isset($record['entries']) && is_array($record['entries']) && 
                             array_reduce($record['entries'], function($carry, $entry) {
                                 return $carry || strpos($entry, 'RRSIG') !== false;
                             }, false))) {
                        $has_rrsig = true;
                        $dnssec_records[] = $record;
                    }
                }
                
                $this->addDebug('DNSSEC', 'DNSSEC detection results:', [
                    'has_rrsig' => $has_rrsig,
                    'has_dnskey' => $has_dnskey,
                    'dnssec_records' => $dnssec_records
                ]);
                
                if ($has_rrsig) {
                    return [
                        'status' => 'good',
                        'message' => 'DNSSEC is enabled and working (RRSIG records found)',
                        'records' => [
                            'has_rrsig' => true,
                            'has_dnskey' => $has_dnskey,
                            'found_records' => $dnssec_records
                        ]
                    ];
                }
                
                // Check for DNSKEY as a fallback
                if ($has_dnskey) {
                    return [
                        'status' => 'warning',
                        'message' => 'DNSSEC appears to be partially configured (DNSKEY found but no RRSIG)',
                        'records' => [
                            'has_rrsig' => false,
                            'has_dnskey' => true,
                            'found_records' => $dnssec_records
                        ]
                    ];
                }
                
                return [
                    'status' => 'bad', 
                    'message' => 'DNSSEC not detected',
                    'debug_info' => [
                        'total_records_found' => count($all_records),
                        'record_types_found' => array_unique(array_map(function($record) {
                            return isset($record['type']) ? $record['type'] : 'unknown';
                        }, $all_records))
                    ]
                ];
            } catch (Exception $e) {
                $this->addDebug('DNSSEC', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkDane($domain) {
            try {
                $this->addDebug('DANE', 'Starting DANE check for: ' . $domain);

                // First check if DNSSEC is enabled (required for DANE)
                $dnssec_result = $this->checkDnssec($domain);
                if ($dnssec_result['status'] !== 'good') {
                    return [
                        'status' => 'bad',
                        'message' => 'DANE requires valid DNSSEC configuration',
                        'dnssec_status' => $dnssec_result
                    ];
                }

                // Get MX records
                $mx_records = dns_get_record($domain, DNS_MX);
                $this->addDebug('DANE', 'Found MX records', $mx_records);

                if (!empty($mx_records)) {
                    foreach ($mx_records as $mx) {
                        $mx_host = rtrim($mx['target'], '.');
                        $this->addDebug('DANE', 'Checking MX host: ' . $mx_host);

                        // Check standard SMTP ports for TLSA records
                        $check_locations = [
                            '_25._tcp.',
                            '_465._tcp.',
                            '_587._tcp.'
                        ];

                        foreach ($check_locations as $prefix) {
                            $check_domain = $prefix . $mx_host;
                            
                            // Get all records
                            $records = @dns_get_record($check_domain, DNS_ANY);
                            $this->addDebug('DANE', 'Checking records for ' . $check_domain, $records);
                            
                            foreach ($records as $record) {
                                if (isset($record['type'])) {
                                    // Check for TLSA records
                                    if ($record['type'] === 'TLSA') {
                                        return [
                                            'status' => 'good',
                                            'message' => 'DANE is configured with TLSA records for ' . $mx_host,
                                            'records' => [
                                                'tlsa' => $record,
                                                'port' => str_replace(['_', '._tcp.'], '', $prefix)
                                            ]
                                        ];
                                    }
                                    
                                    // Also check TXT records for TLSA data
                                    if ($record['type'] === 'TXT' && 
                                        isset($record['txt']) && 
                                        strpos($record['txt'], 'TLSA') !== false) {
                                        return [
                                            'status' => 'warning',
                                            'message' => 'Possible DANE configuration found in TXT record for ' . $mx_host,
                                            'records' => [
                                                'txt' => $record,
                                                'port' => str_replace(['_', '._tcp.'], '', $prefix)
                                            ]
                                        ];
                                    }
                                }
                            }
                        }
                    }
                }

                return ['status' => 'bad', 'message' => 'No DANE records found'];
            } catch (Exception $e) {
                $this->addDebug('DANE', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkSpf($domain) {
            try {
                $this->addDebug('SPF', 'Checking SPF for: ' . $domain);
                $records = dns_get_record($domain, DNS_TXT);
                $this->addDebug('SPF', 'Found TXT records', $records);

                foreach ($records as $record) {
                    if (isset($record['txt']) && strpos($record['txt'], 'v=spf1') === 0) {
                        $strength = $this->analyzeSpfStrength($record['txt']);
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
                $this->addDebug('SPF', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function analyzeSpfStrength($record) {
            if (strpos($record, '-all') !== false) {
                return 'strong';
            } else if (strpos($record, '~all') !== false) {
                return 'medium';
            }
            return 'weak';
        }

        private function checkDmarc($domain) {
            try {
                $this->addDebug('DMARC', 'Checking DMARC for: ' . $domain);
                $records = dns_get_record('_dmarc.' . $domain, DNS_TXT);
                $this->addDebug('DMARC', 'Found records', $records);

                foreach ($records as $record) {
                    if (isset($record['txt']) && strpos($record['txt'], 'v=DMARC1') === 0) {
                        $strength = $this->analyzeDmarcStrength($record['txt']);
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
                $this->addDebug('DMARC', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function analyzeDmarcStrength($record) {
            if (strpos($record, 'p=reject') !== false) {
                return 'strong';
            } else if (strpos($record, 'p=quarantine') !== false) {
                return 'medium';
            }
            return 'weak';
        }

        private function checkTls($domain) {
            try {
                $this->addDebug('TLS', 'Checking TLS for: ' . $domain);
                $mxRecords = dns_get_record($domain, DNS_MX);
                $this->addDebug('TLS', 'Found MX records', $mxRecords);

                if (!empty($mxRecords)) {
                    return [
                        'status' => 'good',
                        'message' => 'MX records found, TLS support assumed'
                    ];
                }
                return ['status' => 'bad', 'message' => 'No MX records found'];
            } catch (Exception $e) {
                $this->addDebug('TLS', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkTlsReport($domain) {
            try {
                $this->addDebug('TLS-Report', 'Checking TLS reporting for: ' . $domain);
                $records = dns_get_record('_smtp._tls.' . $domain, DNS_TXT);
                $this->addDebug('TLS-Report', 'Found records', $records);

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
                $this->addDebug('TLS-Report', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkMtaSts($domain) {
            try {
                $this->addDebug('MTA-STS', 'Checking MTA-STS for: ' . $domain);
                $records = dns_get_record('_mta-sts.' . $domain, DNS_TXT);
                $this->addDebug('MTA-STS', 'Found records', $records);

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
                $this->addDebug('MTA-STS', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkBimi($domain) {
            try {
                $this->addDebug('BIMI', 'Checking BIMI for: ' . $domain);
                $records = dns_get_record('default._bimi.' . $domain, DNS_TXT);
                $this->addDebug('BIMI', 'Found records', $records);

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
                $this->addDebug('BIMI', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }
    }
    ?>
