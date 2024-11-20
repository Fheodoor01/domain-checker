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

        // Your existing checker methods here (from the previous check.php)
        // ... [All the methods from your original DomainChecker class]
    }
    ?>
