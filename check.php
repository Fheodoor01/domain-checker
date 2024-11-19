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
                foreach ($records as $record) {
                    if (strpos($record['txt'], 'v=spf1') === 0) {
                        return $this->analyzeSpf($record['txt']);
                    }
                }
                return ['status' => 'bad', 'message' => 'No SPF record found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed'];
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
                foreach ($records as $record) {
                    if (strpos($record['txt'], 'v=DMARC1') !== false) {
                        return $this->analyzeDmarc($record['txt']);
                    }
                }
                return ['status' => 'bad', 'message' => 'No DMARC record found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed'];
            }
        }

        private function analyzeDmarc($record) {
            $strength = 'weak';
            if (strpos($record, 'p=reject') !== false) {
                $strength = 'strong';
            } elseif (strpos($record, 'p=quarantine') !== false) {
                $strength = 'medium';
            }

            return [
                'status' => 'good',
                'strength' => $strength,
                'record' => $record
            ];
        }

        private function checkDkim($domain) {
            $results = [];
            foreach ($this->config['dns']['dkim_selectors'] as $selector) {
                try {
                    $records = dns_get_record($selector . '._domainkey.' . $domain, DNS_TXT);
                    if ($records) {
                        foreach ($records as $record) {
                            if (strpos($record['txt'], 'v=DKIM1') !== false) {
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
                    $results[$selector] = ['status' => 'error', 'message' => 'Check failed'];
                }
            }
            return $results;
        }

        private function checkBimi($domain) {
            try {
                $records = dns_get_record('default._bimi.' . $domain, DNS_TXT);
                foreach ($records as $record) {
                    if (strpos($record['txt'], 'v=BIMI1') !== false) {
                        return [
                            'status' => 'good',
                            'record' => $record['txt']
                        ];
                    }
                }
                return ['status' => 'bad', 'message' => 'No BIMI record found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed'];
            }
        }

        private function checkZoneTransfer($domain) {
            try {
                $ns_records = dns_get_record($domain, DNS_NS);
                if (!$ns_records) {
                    return ['status' => 'error', 'message' => 'No NS records found'];
                }

                foreach ($ns_records as $ns) {
                    $nameserver = $ns['target'];
                    $output = [];
                    exec("dig @{$nameserver} {$domain} AXFR +noall +answer", $output, $return_var);
                    
                    if (!empty($output)) {
                        return [
                            'status' => 'bad',
                            'message' => "Zone transfer possible from {$nameserver}"
                        ];
                    }
                }
                return ['status' => 'good', 'message' => 'Zone transfer not allowed'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed'];
            }
        }

        private function checkDnssec($domain) {
            try {
                $dnskey_records = dns_get_record($domain, DNS_DNSKEY);
                $ds_records = dns_get_record($domain, DNS_DS);
                
                if ($dnskey_records || $ds_records) {
                    $details = [];
                    if ($dnskey_records) {
                        $details[] = "DNSKEY records found (" . count($dnskey_records) . ")";
                    }
                    if ($ds_records) {
                        $details[] = "DS records found (" . count($ds_records) . ")";
                    }
                    return [
                        'status' => 'good',
                        'message' => implode(', ', $details)
                    ];
                }
                return ['status' => 'bad', 'message' => 'No DNSSEC records found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed'];
            }
        }
    }
    ?>
