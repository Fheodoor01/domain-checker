<?php
    function detectLanguage() {
        session_start();
        
        // Check if language is being switched
        if (isset($_GET['lang']) && in_array($_GET['lang'], ['en', 'nl'])) {
            $_SESSION['language'] = $_GET['lang'];
            return $_GET['lang'];
        }
        
        // Use session language if set
        if (isset($_SESSION['language'])) {
            return $_SESSION['language'];
        }
        
        // Default to English
        return 'en';
    }
    ?>
