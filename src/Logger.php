<?php
    namespace DomainChecker;

    class Logger {
        private $directory;
        private $level;
        private $levels = ['debug' => 0, 'info' => 1, 'warning' => 2, 'error' => 3];
        
        public function __construct($config) {
            $this->directory = $config['directory'];
            $this->level = $config['level'];
            
            if (!is_dir($this->directory)) {
                mkdir($this->directory, 0755, true);
            }
        }
        
        public function log($level, $message, array $context = []) {
            if ($this->levels[$level] >= $this->levels[$this->level]) {
                $logEntry = date('Y-m-d H:i:s') . " [$level] " . 
                           $this->interpolate($message, $context) . PHP_EOL;
                
                file_put_contents(
                    $this->directory . '/' . date('Y-m-d') . '.log',
                    $logEntry,
                    FILE_APPEND
                );
            }
        }
        
        private function interpolate($message, array $context = []) {
            $replace = [];
            foreach ($context as $key => $val) {
                $replace['{' . $key . '}'] = $val;
            }
            return strtr($message, $replace);
        }
    }
    ?>
