<?php
    // Add this method to the DomainChecker class
    private function checkBIMI($domain) {
        try {
            // First check if DMARC is properly configured (required for BIMI)
            $dmarcResult = $this->checkDMARC($domain);
            if ($dmarcResult['status'] !== 'good' || 
                (!isset($dmarcResult['strength']) || $dmarcResult['strength'] !== 'strong')) {
                return [
                    'status' => 'bad',
                    'message' => 'BIMI requires strict DMARC policy (p=reject)',
                    'details' => 'Configure DMARC with p=reject before implementing BIMI'
                ];
            }

            // Check default BIMI record
            $records = dns_get_record('default._bimi.' . $domain, DNS_TXT);
            if (!empty($records)) {
                foreach ($records as $record) {
                    if (isset($record['txt']) && strpos($record['txt'], 'v=BIMI1') === 0) {
                        // Parse BIMI record to check for required fields
                        $hasSVG = strpos($record['txt'], 'l=') !== false;
                        $hasVMC = strpos($record['txt'], 'a=') !== false;
                        
                        $status = $hasVMC ? 'good' : 'warning';
                        $message = $hasVMC ? 
                            'BIMI record found with VMC certificate' : 
                            'BIMI record found but missing VMC certificate';
                        
                        $details = [];
                        if ($hasSVG) $details[] = 'SVG logo URL present';
                        if ($hasVMC) $details[] = 'VMC certificate present';
                        
                        return [
                            'status' => $status,
                            'message' => $message,
                            'record' => $record['txt'],
                            'details' => implode(', ', $details)
                        ];
                    }
                }
            }
            
            return [
                'status' => 'bad',
                'message' => 'No BIMI record found',
                'details' => 'Add a BIMI record to display your logo in supporting email clients'
            ];
        } catch (Exception $e) {
            return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
        }
    }

    // Update the checkAll method to include BIMI
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
            'bimi' => $this->checkBIMI($domain)  // Add BIMI check
        ];

        // Update weights in calculateScore method
        $score = $this->calculateScore($results);
        $results['overall_score'] = $score;

        return $results;
    }

    // Update the calculateScore method to include BIMI
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
            'bimi' => 0.25  // Add BIMI weight
        ];

        $score = 0;
        $totalWeight = 0;

        foreach ($weights as $check => $weight) {
            if (isset($results[$check]['status'])) {
                $totalWeight += $weight;
                if ($results[$check]['status'] === 'good') {
                    $score += $weight;
                } else if ($results[$check]['status'] === 'warning') {
                    $score += ($weight * 0.5); // Half points for warnings
                }
            }
        }

        return number_format(($score / $totalWeight) * 5, 2);
    }
    ?>
