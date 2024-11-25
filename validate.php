<?php

function validateDomain($domain) {
    // Sanitize domain input
    $domain = escapeshellarg(trim($domain));
    
    // Use dig command to check DNSSEC
    $command = "dig +dnssec " . $domain;
    $output = shell_exec($command);
    
    if ($output === null) {
        return false;
    }
    
    // Check for authenticated data flag (ad) and RRSIG
    $hasAD = (strpos($output, 'flags: qr rd ra ad;') !== false);
    $hasRRSIG = (strpos($output, 'RRSIG') !== false);
    
    // Domain has valid DNSSEC if both AD flag is set and RRSIG records exist
    return ($hasAD && $hasRRSIG);
}