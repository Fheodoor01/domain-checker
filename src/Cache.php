<?php
    namespace DomainChecker;

    class Cache {
        private $directory;
        private $duration;
        
        public function __construct($config) {
            $this->directory = $config['directory'];
            $this->duration = $config['duration'];
            
            if (!is_dir($this->directory)) {
                mkdir($this->directory, 0755, true);
            }
        }
        
        public function get($key) {
            $file = $this->getFilePath($key);
            if (!file_exists($file)) {
                return null;
            }
            
            $data = json_decode(file_get_contents($file), true);
            if ($data['expires'] < time()) {
                unlink($file);
                return null;
            }
            
            return $data['value'];
        }
        
        public function set($key, $value) {
            $data = [
                'expires' => time() + $this->duration,
                'value' => $value
            ];
            
            file_put_contents(
                $this->getFilePath($key),
                json_encode($data)
            );
        }
        
        private function getFilePath($key) {
            return $this->directory . '/' . md5($key) . '.cache';
        }
    }
    ?>
