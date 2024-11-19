<?php
    namespace DomainChecker;

    class DnsChecker {
        private $config;
        private $cache;
        private $logger;
        
        public function __construct($config, Cache $cache, Logger $logger) {
            $this->config = $config;
            $this->cache = $cache;
            $this->logger = $logger;
        }
        
        public function checkAll($domain) {
            $cacheKey = 'domain_' . $domain;
            if ($cached = $this->cache->get($cacheKey)) {
                return $cached;
            }
            
            $results = [
                'spf' => $this->checkSpf($domain),
                'dmarc' => $this->checkDmarc($domain),
                'dkim' => $this->checkDkim($domain),
                'bimi' => $this->checkBimi($domain),
                'zone_transfer' => $this->checkZoneTransfer($domain),
                'dnssec' => $this->checkDnssec($domain)
            ];
            
            $this->cache->set($cacheKey, $results);
            return $results;
        }
        
        private function checkSpf($domain) {
            try {
                $records = $this->dnsQuery($domain, DNS_TXT);
                foreach ($records as $record) {
                    if (strpos($record['txt'], 'v=spf1') === 0) {
                        return $this->analyzeSpf($record['txt']);
                    }
                }
                return ['status' => 'bad', 'message' => 'No SPF record found'];
            } catch (\Exception $e) {
                $this->logger->log('error', 'SPF check failed: {message}', ['message' => $e->getMessage()]);
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
        
        // Similar detailed implementations for DMARC, DKIM, BIMI, etc.
        // ... (implementation of other check methods)
        
        private function dnsQuery($domain, $type, $retry = 0) {
            $options = [
                'timeout' => $this->config['dns']['timeout'],
                'retry' => $this->config['dns']['retry']
            ];
            
            try {
                return dns_get_record($domain, $type);
            } catch (\Exception $e) {
                if ($retry < $options['retry']) {
                    sleep(1);
                    return $this->dnsQuery($domain, $type, $retry + 1);
                }
                throw $e;
            }
        }
    }
    ?>
