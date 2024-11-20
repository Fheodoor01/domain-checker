<?php
    function detectLanguage() {
        // Check if language is set in session
        session_start();
        if (isset($_SESSION['language'])) {
            return $_SESSION['language'];
        }

        // Check if language is set in GET parameter
        if (isset($_GET['lang']) && in_array($_GET['lang'], ['en', 'nl'])) {
            $_SESSION['language'] = $_GET['lang'];
            return $_GET['lang'];
        }

        // Detect language from browser headers
        $accept_language = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        $langs = explode(',', $accept_language);
        foreach ($langs as $lang) {
            $lang = substr($lang, 0, 2);
            if ($lang == 'nl') {
                // Check if IP is from Netherlands or Belgium
                $ip = $_SERVER['REMOTE_ADDR'];
                $country = geoip_country_code_by_name($ip);
                if ($country == 'NL' || $country == 'BE') {
                    $_SESSION['language'] = 'nl';
                    return 'nl';
                }
            }
        }

        // Default to English
        $_SESSION['language'] = 'en';
        return 'en';
    }
    ?>
