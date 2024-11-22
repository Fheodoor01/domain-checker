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

        private function checkDnssecUsingDig($domain) {
            try {
                $command = sprintf('dig +dnssec %s', escapeshellarg($domain));
                $output = [];
                $return_var = 0;
                exec($command, $output, $return_var);
                
                $this->addDebug('DNSSEC', 'Dig command output:', $output);
                
                if ($return_var !== 0) {
                    return false;
                }
                
                // Look for DNSSEC indicators in dig output
                $output_str = implode("\n", $output);
                if (strpos($output_str, 'RRSIG') !== false || 
                    strpos($output_str, 'DNSKEY') !== false || 
                    strpos($output_str, 'flags: do') !== false) {
                    return true;
                }
                
                return false;
            } catch (Exception $e) {
                $this->addDebug('DNSSEC', 'Dig check error: ' . $e->getMessage());
                return false;
            }
        }

        private function checkDnssecUsingDNS($domain) {
            try {
                // Try to get DNSSEC-related records
                $records = @dns_get_record($domain, DNS_ANY);
                $this->addDebug('DNSSEC', 'DNS query result:', $records);
                
                if (!empty($records)) {
                    foreach ($records as $record) {
                        if (isset($record['type']) && in_array($record['type'], ['DNSKEY', 'DS', 'RRSIG'])) {
                            return true;
                        }
                    }
                }
                
                // Try parent domain
                $parent = substr($domain, strpos($domain, '.') + 1);
                $parent_records = @dns_get_record($parent, DNS_ANY);
                $this->addDebug('DNSSEC', 'Parent domain records:', $parent_records);
                
                if (!empty($parent_records)) {
                    foreach ($parent_records as $record) {
                        if (isset($record['type']) && in_array($record['type'], ['DS'])) {
                            return true;
                        }
                    }
                }
                
                return false;
            } catch (Exception $e) {
                $this->addDebug('DNSSEC', 'DNS check error: ' . $e->getMessage());
                return false;
            }
        }

        private function checkDnssecUsingTXT($domain) {
            try {
                $txt_records = @dns_get_record($domain, DNS_TXT);
                $this->addDebug('DNSSEC', 'TXT records:', $txt_records);
                
                if (!empty($txt_records)) {
                    foreach ($txt_records as $record) {
                        if (isset($record['txt'])) {
                            $txt = strtolower($record['txt']);
                            if (strpos($txt, 'dnssec') !== false || 
                                strpos($txt, 'rrsig') !== false || 
                                strpos($txt, 'dnskey') !== false) {
                                return true;
                            }
                        }
                    }
                }
                
                return false;
            } catch (Exception $e) {
                $this->addDebug('DNSSEC', 'TXT check error: ' . $e->getMessage());
                return false;
            }
        }

        private function checkDnssec($domain) {
            try {
                $this->addDebug('DNSSEC', 'Starting DNSSEC check for: ' . $domain);
                
                // First try dig command as it's most reliable
                $dig_result = $this->checkDnssecUsingDig($domain);
                if ($dig_result) {
                    return [
                        'status' => 'good',
                        'message' => 'DNSSEC is enabled (detected via dig)',
                        'detection_method' => 'dig'
                    ];
                }
                
                // Try PHP DNS methods as fallback
                $methods = [
                    'DNS' => $this->checkDnssecUsingDNS($domain),
                    'TXT' => $this->checkDnssecUsingTXT($domain)
                ];
                
                $this->addDebug('DNSSEC', 'Detection methods results:', $methods);
                
                // If any method detected DNSSEC, consider it enabled
                if (in_array(true, $methods, true)) {
                    return [
                        'status' => 'good',
                        'message' => 'DNSSEC appears to be enabled',
                        'detection_methods' => array_keys(array_filter($methods))
                    ];
                }
                
                // Check if the domain exists but DNSSEC is not enabled
                $a_record = @dns_get_record($domain, DNS_A);
                if (!empty($a_record)) {
                    return [
                        'status' => 'bad',
                        'message' => 'Domain exists but DNSSEC is not detected',
                        'debug_info' => [
                            'methods_tried' => array_merge(['dig' => $dig_result], $methods),
                            'has_a_record' => true
                        ]
                    ];
                }
                
                return [
                    'status' => 'error',
                    'message' => 'Could not determine DNSSEC status',
                    'debug_info' => [
                        'methods_tried' => array_merge(['dig' => $dig_result], $methods),
                        'has_a_record' => false
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
