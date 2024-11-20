<?php
    // Only add this new method to your existing DomainChecker class
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
            return [
                'status' => 'bad',
                'message' => 'No BIMI record found'
            ];
        } catch (Exception $e) {
            return ['status' => 'error', 'message' => 'Check failed: ' . $e->getMessage()];
        }
    }

    // Update your existing checkAll method to include BIMI
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

        // Calculate overall score
        $score = $this->calculateScore($results);
        $results['overall_score'] = $score;

        return $results;
    }

    // Update your existing calculateScore method to include BIMI
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
                }
            }
        }

        return number_format(($score / $totalWeight) * 5, 2);
    }
    ?>
