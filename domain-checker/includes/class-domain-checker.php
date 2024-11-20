<?php
    class DomainChecker {
        private $config;
        
        public function __construct() {
            $this->config = array(
                'dns' => array(
                    'timeout' => 5,
                    'retry' => 3,
                    'dkim_selectors' => array('default', 'google', 'selector1', 'selector2', 'dkim', 'mail')
                )
            );
        }
        
        public function checkAll($domain) {
            $results = array(
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
            );

            $score = $this->calculateScore($results);
            $results['overall_score'] = $score;

            return $results;
        }

        private function calculateScore($results) {
            $weights = array(
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
            );

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

        // Copy all the check methods from our previous working code
        private function checkNameServers($domain) {
            try {
                $records = dns_get_record($domain, DNS_NS);
                if (count($records) >= 2) {
                    return array(
                        'status' => 'good',
                        'message' => 'Found ' . count($records) . ' name servers',
                        'records' => array_map(function($r) { return $r['target']; }, $records)
                    );
                } else if (count($records) === 1) {
                    return array(
                        'status' => 'warning',
                        'message' => 'Only one name server found. Multiple name servers are recommended.',
                        'records' => array_map(function($r) { return $r['target']; }, $records)
                    );
                }
                return array('status' => 'bad', 'message' => 'No name servers found');
            } catch (Exception $e) {
                return array('status' => 'error', 'message' => 'Check failed: ' . $e->getMessage());
            }
        }

        // ... [Continue with all other check methods from our previous code]
        // Include checkSMTP, checkDNSSEC, checkSPF, checkDMARC, checkDANE,
        // checkTLS, checkTLSReport, checkMTASTS, and checkBIMI methods
        // exactly as they were in our working version

    }
    ?>
