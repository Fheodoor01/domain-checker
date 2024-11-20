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

                return ['status' => 'bad', 'message' => 'DNSSEC not detected'];
            } catch (Exception $e) {
                $this->addDebug('DNSSEC', 'Error: ' . $e->getMessage());
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
