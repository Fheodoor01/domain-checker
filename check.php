<?php
    class DomainChecker {
        private $config;
        
        public function __construct($config) {
            $this->config = $config;
        }
        
        public function checkAll($domain) {
            return [
                'spf' => $this->checkSpf($domain),
                'dmarc' => $this->checkDmarc($domain),
                'dkim' => $this->checkDkim($domain),
                'bimi' => $this->checkBimi($domain),
                'zone_transfer' => $this->checkZoneTransfer($domain),
                'dnssec' => $this->checkDnssec($domain)
            ];
        }
        
        private function checkSpf($domain) {
            try {
                $records = dns_get_record($domain, DNS_TXT);
                if ($records) {
                    foreach ($records as $record) {
                        if (isset($record['txt']) && strpos($record['txt'], 'v=spf1') === 0) {
                            return $this->analyzeSpf($record['txt']);
                        }
                    }
                }
                return ['status' => 'bad', 'message' => 'No SPF record found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function analyzeSpf($record) {
            $mechanisms = explode(' ', $record);
            $strength = 'weak';
            
            if (strpos($record, '-all') !== false) {
                $strength = 'strong';
            } elseif (strpos($record, '~all') !== false) {
                $strength = 'medium';
            }
            
            return [
                'status' => 'good',
                'strength' => $strength,
                'record' => $record,
                'mechanisms' => array_filter($mechanisms)
            ];
        }

        private function checkDmarc($domain) {
            try {
                $records = dns_get_record('_dmarc.' . $domain, DNS_TXT);
                if ($records) {
                    foreach ($records as $record) {
                        if (isset($record['txt']) && strpos($record['txt'], 'v=DMARC1') === 0) {
                            return [
                                'status' => 'good',
                                'record' => $record['txt'],
                                'strength' => $this->analyzeDmarcStrength($record['txt'])
                            ];
                        }
                    }
                }
                return ['status' => 'bad', 'message' => 'No DMARC record found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function analyzeDmarcStrength($record) {
            if (strpos($record, 'p=reject') !== false) {
                return 'strong';
            } elseif (strpos($record, 'p=quarantine') !== false) {
                return 'medium';
            }
            return 'weak';
        }

        private function checkDkim($domain) {
            $results = [];
            foreach ($this->config['dns']['dkim_selectors'] as $selector) {
                try {
                    $records = dns_get_record($selector . '._domainkey.' . $domain, DNS_TXT);
                    if ($records) {
                        foreach ($records as $record) {
                            if (isset($record['txt']) && strpos($record['txt'], 'v=DKIM1') === 0) {
                                $results[$selector] = [
                                    'status' => 'good',
                                    'record' => $record['txt']
                                ];
                                continue 2;
                            }
                        }
                    }
                    $results[$selector] = ['status' => 'bad', 'message' => 'No DKIM record found'];
                } catch (Exception $e) {
                    $results[$selector] = ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
                }
            }
            return $results;
        }

        private function checkBimi($domain) {
            try {
                $records = dns_get_record('default._bimi.' . $domain, DNS_TXT);
                if ($records) {
                    foreach ($records as $record) {
                        if (isset($record['txt']) && strpos($record['txt'], 'v=BIMI1') === 0) {
                            return [
                                'status' => 'good',
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

        private function checkZoneTransfer($domain) {
            try {
                $ns_records = dns_get_record($domain, DNS_NS);
                if (!$ns_records) {
                    return ['status' => 'error', 'message' => 'No NS records found'];
                }
                
                return [
                    'status' => 'info',
                    'message' => 'NS records found: ' . implode(', ', array_map(function($r) { 
                        return $r['target']; 
                    }, $ns_records))
                ];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkDnssec($domain) {
            try {
                $records = dns_get_record($domain, DNS_ANY);
                $hasDnssec = false;
                $details = [];
                
                foreach ($records as $record) {
                    if ($record['type'] === 'RRSIG' || $record['type'] === 'DNSKEY') {
                        $hasDnssec = true;
                        $details[] = "Found {$record['type']} record";
                    }
                }
                
                if ($hasDnssec) {
                    return [
                        'status' => 'good',
                        'message' => implode(', ', $details)
                    ];
                }
                
                return ['status' => 'bad', 'message' => 'No DNSSEC records found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }
    }
    ?>
