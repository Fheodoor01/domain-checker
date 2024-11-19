<?php
    namespace DomainChecker;

    class RateLimit {
        private $cache;
        private $limit;
        
        public function __construct($limit, Cache $cache) {
            $this->limit = $limit;
            $this->cache = $cache;
        }
        
        public function check($ip) {
            $key = 'rate_limit_' . $ip;
            $current = $this->cache->get($key) ?? ['count' => 0, 'reset' => time() + 3600];
            
            if ($current['reset'] < time()) {
                $current = ['count' => 0, 'reset' => time() + 3600];
            }
            
            if ($current['count'] >= $this->limit) {
                return false;
            }
            
            $current['count']++;
            $this->cache->set($key, $current);
            return true;
        }
    }
    ?>
