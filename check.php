<?php

namespace DomainChecker;

require_once __DIR__ . '/src/Security.php';
require_once __DIR__ . '/src/Logger.php';

    class DomainChecker {
        private $config;
        private $debug = [];
        private $logger;
        private $security_risks = [];
        
        public function __construct($config) {
            $this->config = $config;
            $this->logger = new Logger();
        }
        
        public function checkAll($domain) {
            $this->debug = []; // Reset debug info
            $this->security_risks = []; // Reset security risks
            
            // Check nameservers first
            $security = new Security();
            $domain = $security->sanitizeDomain($domain);
            
            if ($domain === null) {
                $this->logger->logCheck($domain, 'Error: Invalid domain provided');
                return "Invalid domain provided";
            }
            
            // Check if domain exists
            $command = sprintf('dig +short NS %s', escapeshellarg($domain));
            $output = Security::safeExecute('dig', ['+short', 'NS', $domain])['output'];
            
            if (empty(trim($output ?? ''))) {
                // No nameservers found, domain likely doesn't exist
                $this->logger->logCheck($domain, 'Error: Domain does not exist');
                return 'Error: Domain does not exist';
            }
            
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
                'bimi' => $this->checkBimi($domain),
                'https' => $security->checkHttps($domain),  // Add HTTPS check
                'reverse_dns' => $this->checkReverseDNS($domain),
                'caa' => $this->checkCAA($domain)
            ];

            // Detect services from SPF and DMARC records
            $services = $this->detectServices($results['spf'], $results['dmarc']);

            $score = $this->calculateScore($results);
            $results['overall_score'] = $score;
            $results['detected_services'] = $services;
            $results['security_risks'] = $this->security_risks;
            $results['debug'] = $this->debug;

            // Log the check with results
            $this->logger->logCheck($domain, $results);

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
                'bimi' => 0.25,
                'https' => 0.5,
                'reverse_dns' => 0.25,
                'caa' => 0.25
            ];

            $score = 0;
            $totalWeight = 0;

            foreach ($weights as $check => $weight) {
                if (isset($results[$check]['status'])) {
                    $totalWeight += $weight;
                    if ($results[$check]['status'] === 'good' || $results[$check]['status'] === true) {
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
                
                // Use the validateDomain function
                require_once('validate.php');
                try {
                    $result = validateDomain($domain);
                    if ($result === true) {
                        return [
                            'status' => 'good',
                            'message' => 'DNSSEC is properly configured and valid'
                        ];
                    }
                } catch (Metaregistrar\DNS\dnsException $e) {
                    $this->addDebug('DNSSEC', 'DNSSEC validation error: ' . $e->getMessage());
                    return [
                        'status' => 'bad',
                        'message' => 'DNSSEC validation failed: ' . $e->getMessage()
                    ];
                }
                
                return [
                    'status' => 'bad',
                    'message' => 'DNSSEC is not properly configured'
                ];
            } catch (Exception $e) {
                $this->addDebug('DNSSEC', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkDane($domain) {
            try {
                $this->addDebug('DANE', 'Starting DANE check for: ' . $domain);
                
                // Ensure DNSSEC is valid before checking DANE
                $dnssec_status = $this->checkDnssec($domain);
                if ($dnssec_status['status'] !== 'good') {
                    return [
                        'status' => 'bad',
                        'message' => 'DANE check failed because DNSSEC is not valid'
                    ];
                }
                
                // First get MX records
                $command = sprintf('dig +short MX %s', escapeshellarg($domain));
                $mx_output = Security::safeExecute('dig', ['+short', 'MX', $domain])['output'];
                
                if (empty(trim($mx_output ?? ''))) {
                    return [
                        'status' => 'bad',
                        'message' => 'No MX records found'
                    ];
                }
                
                // Parse MX records
                $mx_records = array_filter(explode("\n", trim($mx_output)));
                $ports = [25, 465, 587]; // Common SMTP ports
                
                foreach ($mx_records as $mx_record) {
                    // MX record format: priority hostname
                    if (preg_match('/^\d+\s+(.+?)\.?$/', trim($mx_record), $matches)) {
                        $mx_host = rtrim($matches[1], '.');
                        
                        foreach ($ports as $port) {
                            // Check for TLSA records for each port
                            $tlsa_domain = sprintf('_%d._tcp.%s', $port, $mx_host);
                            // Use dig without +short to get full output including RRSIG
                            $command = sprintf('dig +dnssec TLSA %s', escapeshellarg($tlsa_domain));
                            $output = Security::safeExecute('dig', ['+dnssec', 'TLSA', $tlsa_domain])['output'];
                            
                            if (!empty($output)) {
                                $has_valid_tlsa = false;
                                $has_rrsig = false;
                                $valid_records = [];
                                
                                // Parse the dig output
                                $lines = explode("\n", $output);
                                foreach ($lines as $line) {
                                    // Check for TLSA records
                                    if (strpos($line, 'TLSA') !== false && strpos($line, 'RRSIG') === false) {
                                        // Extract just the TLSA data
                                        if (preg_match('/TLSA\s+(\d+)\s+(\d+)\s+(\d+)\s+([A-F0-9]+)/i', $line, $matches)) {
                                            $usage = (int)$matches[1];
                                            $selector = (int)$matches[2];
                                            $matching_type = (int)$matches[3];
                                            
                                            // Validate TLSA record format
                                            if (($usage >= 0 && $usage <= 3) && 
                                                ($selector >= 0 && $selector <= 1) && 
                                                ($matching_type >= 0 && $matching_type <= 2)) {
                                                $has_valid_tlsa = true;
                                                $valid_records[] = sprintf("%d %d %d %s", $usage, $selector, $matching_type, $matches[4]);
                                            }
                                        }
                                    }
                                    // Check for RRSIG record
                                    if (strpos($line, 'RRSIG') !== false && strpos($line, 'TLSA') !== false) {
                                        $has_rrsig = true;
                                    }
                                }
                                
                                // Only consider DANE valid if we have both TLSA and RRSIG
                                if ($has_valid_tlsa && $has_rrsig) {
                                    return [
                                        'status' => 'good',
                                        'message' => sprintf('DANE is enabled (Valid TLSA records found for %s port %d)', $mx_host, $port),
                                        'mx_host' => $mx_host,
                                        'port' => $port,
                                        'tlsa_records' => $valid_records
                                    ];
                                }
                            }
                        }
                    }
                }
                
                return [
                    'status' => 'bad',
                    'message' => 'No valid TLSA records found for MX hosts, DANE is not enabled'
                ];
            } catch (Exception $e) {
                $this->addDebug('DANE', 'Error: ' . $e->getMessage());
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function detectServices($spfRecord = null, $dmarcRecord = null) {
            $detectedServices = [];
            $spfProviders = json_decode(file_get_contents(__DIR__ . '/complete-saas-spf-records.json'), true)['providers'];
            $unidentifiedRecordsFile = __DIR__ . '/unidentified_spf_records.json';
            
            // Group providers by SPF include
            $spfGroups = [];
            foreach ($spfProviders as $provider) {
                if ($provider['spf_include']) {
                    $spfGroups[$provider['spf_include']][] = $provider;
                }
            }
            
            if ($spfRecord && isset($spfRecord['record'])) {
                $spfText = strtolower($spfRecord['record']);
                
                // Extract all include mechanisms for logging unidentified records
                preg_match_all('/include:([^\s]+)/', $spfText, $matches);
                $includes = $matches[1] ?? [];
                $identifiedIncludes = [];
                
                // Check for each SPF group
                foreach ($spfGroups as $spfInclude => $providers) {
                    if (strpos($spfText, $spfInclude) !== false) {
                        // Use the first provider as the main service (usually the most well-known)
                        $mainProvider = $providers[0];
                        $detectedServices[] = [
                            'name' => $mainProvider['name'],
                            'description' => $mainProvider['description']
                        ];
                        $identifiedIncludes[] = $spfInclude;
                    }
                }
                
                // Track unidentified includes (but don't display them)
                $unidentifiedIncludes = array_diff($includes, $identifiedIncludes);
                if (!empty($unidentifiedIncludes)) {
                    $unidentifiedData = [];
                    if (file_exists($unidentifiedRecordsFile)) {
                        $unidentifiedData = json_decode(file_get_contents($unidentifiedRecordsFile), true);
                    }
                    
                    foreach ($unidentifiedIncludes as $include) {
                        if (!in_array($include, $unidentifiedData['unidentified_includes'])) {
                            $unidentifiedData['unidentified_includes'][] = $include;
                        }
                    }
                    
                    $unidentifiedData['last_updated'] = date('Y-m-d H:i:s');
                    file_put_contents($unidentifiedRecordsFile, json_encode($unidentifiedData, JSON_PRETTY_PRINT));
                }
            }

            // Common DMARC management services
            $dmarcServices = [
                'dmarcian' => 'Dmarcian',
                'valimail' => 'Valimail',
                'agari' => 'Agari',
                'proofpoint' => 'Proofpoint',
                'mimecast' => 'Mimecast'
            ];

            if ($dmarcRecord && isset($dmarcRecord['record'])) {
                $dmarcText = strtolower($dmarcRecord['record']);
                foreach ($dmarcServices as $keyword => $serviceName) {
                    if (strpos($dmarcText, $keyword) !== false) {
                        $detectedServices[] = [
                            'name' => $serviceName,
                            'type' => 'DMARC Management'
                        ];
                    }
                }
            }

            return $detectedServices;
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
            } catch (\Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        /**
         * Add a security risk to the results
         * 
         * @param string $title Short title of the security risk
         * @param string $description Detailed description of the risk
         */
        private function addSecurityRisk($title, $description) {
            if (!isset($this->security_risks)) {
                $this->security_risks = [];
            }
            $this->security_risks[] = [
                'title' => $title,
                'description' => $description
            ];
        }

        private function checkReverseDNS($domain) {
            $result = ['status' => 'bad', 'details' => []];
            
            // Get MX records
            $mx_records = dns_get_record($domain, DNS_MX);
            if (empty($mx_records)) {
                $result['details'][] = "No MX records found";
                return $result;
            }
            
            $all_valid = true;
            foreach ($mx_records as $mx) {
                $ip_addresses = gethostbynamel($mx['target']);
                if (!$ip_addresses) {
                    $result['details'][] = "Could not resolve {$mx['target']}";
                    $all_valid = false;
                    continue;
                }
                
                foreach ($ip_addresses as $ip) {
                    $ptr = gethostbyaddr($ip);
                    if ($ptr === $ip || $ptr === false) {
                        $result['details'][] = "No reverse DNS record for {$mx['target']} ({$ip})";
                        $all_valid = false;
                    } else {
                        $result['details'][] = "Reverse DNS for {$mx['target']}: {$ptr}";
                    }
                }
            }
            
            if ($all_valid) {
                $result['status'] = 'good';
            } else {
                $this->addSecurityRisk("Missing reverse DNS records for mail servers", 
                    "Some mail servers lack proper reverse DNS records, which may cause email delivery issues.");
            }
            return $result;
        }
        
        private function checkCAA($domain) {
            $result = ['status' => 'bad', 'details' => []];
            
            // Check CAA records
            $caa_records = dns_get_record($domain, DNS_CAA);
            
            if (empty($caa_records)) {
                $result['details'][] = "No CAA records found";
                $this->addSecurityRisk("Missing CAA records", 
                    "No CAA (Certificate Authority Authorization) records found. CAA records help prevent unauthorized SSL/TLS certificate issuance.");
                return $result;
            }
            
            foreach ($caa_records as $caa) {
                if (isset($caa['tag']) && isset($caa['value'])) {
                    $result['details'][] = "CAA record: {$caa['tag']} => {$caa['value']}";
                }
            }
            
            $result['status'] = 'good';
            return $result;
        }
    }
    ?>
