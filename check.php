<?php
    class DomainChecker {
        private $config;
        
        public function __construct($config) {
            $this->config = $config;
        }

        private function getDnsRecord($domain, $type) {
            $cmd = "dig +short " . escapeshellarg($domain) . " " . $type;
            exec($cmd, $output, $return_var);
            return $output;
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
                $cmd = "dig +short " . escapeshellarg($domain) . " TXT";
                exec($cmd, $output, $return_var);
                
                foreach ($output as $record) {
                    if (strpos($record, 'v=spf1') === 1) { // Records usually start with a quote
                        return $this->analyzeSpf(trim($record, '"'));
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
                $cmd = "dig +short " . escapeshellarg("_dmarc." . $domain) . " TXT";
                exec($cmd, $output, $return_var);
                
                foreach ($output as $record) {
                    if (strpos($record, 'v=DMARC1') === 1) {
                        $record = trim($record, '"');
                        return [
                            'status' => 'good',
                            'record' => $record,
                            'strength' => $this->analyzeDmarcStrength($record)
                        ];
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
                    $cmd = "dig +short " . escapeshellarg($selector . "._domainkey." . $domain) . " TXT";
                    exec($cmd, $output, $return_var);
                    
                    $found = false;
                    foreach ($output as $record) {
                        if (strpos($record, 'v=DKIM1') === 1) {
                            $results[$selector] = [
                                'status' => 'good',
                                'record' => trim($record, '"')
                            ];
                            $found = true;
                            break;
                        }
                    }
                    if (!$found) {
                        $results[$selector] = ['status' => 'bad', 'message' => 'No DKIM record found'];
                    }
                } catch (Exception $e) {
                    $results[$selector] = ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
                }
            }
            return $results;
        }

        private function checkBimi($domain) {
            try {
                $cmd = "dig +short " . escapeshellarg("default._bimi." . $domain) . " TXT";
                exec($cmd, $output, $return_var);
                
                foreach ($output as $record) {
                    if (strpos($record, 'v=BIMI1') === 1) {
                        return [
                            'status' => 'good',
                            'record' => trim($record, '"')
                        ];
                    }
                }
                return ['status' => 'bad', 'message' => 'No BIMI record found'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkZoneTransfer($domain) {
            try {
                $cmd = "dig +short " . escapeshellarg($domain) . " NS";
                exec($cmd, $output, $return_var);
                
                if (empty($output)) {
                    return ['status' => 'error', 'message' => 'No NS records found'];
                }

                foreach ($output as $ns) {
                    $cmd = "dig @" . trim($ns, '.') . " " . escapeshellarg($domain) . " AXFR +noall +answer";
                    exec($cmd, $axfr_output, $return_var);
                    
                    if (!empty($axfr_output)) {
                        return [
                            'status' => 'bad',
                            'message' => "Zone transfer possible from " . trim($ns, '.')
                        ];
                    }
                }
                
                return ['status' => 'good', 'message' => 'Zone transfer not allowed'];
            } catch (Exception $e) {
                return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
            }
        }

        private function checkDnssec($domain) {
            try {
                // Check for DNSKEY records
                $cmd = "dig +short " . escapeshellarg($domain) . " DNSKEY";
                exec($cmd, $dnskey_output, $return_var);
                
                // Check for DS records
                $cmd = "dig +short " . escapeshellarg($domain) . " DS";
                exec($cmd, $ds_output, $return_var);
                
                if (!empty($dnskey_output) || !empty($ds_output)) {
                    $details = [];
                    if (!empty($dnskey_output)) {
                        $details[] = "DNSKEY records found (" . count($dnskey_output) . ")";
                    }
                    if (!empty($ds_output)) {
                        $details[] = "DS records found (" . count($ds_output) . ")";
                    }
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
