<?php
    /*
    Standalone Email Security Checker Script
    Description: A script to check SPF, DMARC, DKIM, BIMI, Zone Transfer, and DNSSEC
    Version: 1.0
    Author: Bolt
    */

    error_reporting(E_ALL);
    ini_set('display_errors', 1);

    function sanitize_domain($domain) {
        return filter_var(trim($domain), FILTER_SANITIZE_STRING);
    }

    function check_spf($domain) {
        $records = dns_get_record($domain, DNS_TXT);
        if ($records) {
            foreach ($records as $record) {
                if (strpos($record['txt'], 'v=spf1') !== false) {
                    return [$record['txt'], 'Good'];
                }
            }
            return ['SPF record not found in TXT records.', 'Bad'];
        }
        return ['No TXT records found.', 'Bad'];
    }

    function check_dmarc($domain) {
        $records = dns_get_record('_dmarc.' . $domain, DNS_TXT);
        if ($records) {
            foreach ($records as $record) {
                if (strpos($record['txt'], 'v=DMARC1') !== false) {
                    return [$record['txt'], 'Good'];
                }
            }
            return ['DMARC record not found in TXT records.', 'Bad'];
        }
        return ['No DMARC records found.', 'Bad'];
    }

    function check_dkim($domain, $selector = 'default') {
        $records = dns_get_record($selector . '._domainkey.' . $domain, DNS_TXT);
        if ($records) {
            foreach ($records as $record) {
                if (strpos($record['txt'], 'v=DKIM1') !== false) {
                    return [$record['txt'], 'Good'];
                }
            }
            return ['DKIM record not found in TXT records.', 'Bad'];
        }
        return ['No DKIM records found.', 'Bad'];
    }

    function check_bimi($domain) {
        $records = dns_get_record('default._bimi.' . $domain, DNS_TXT);
        if ($records) {
            foreach ($records as $record) {
                if (strpos($record['txt'], 'v=BIMI1') !== false) {
                    return [$record['txt'], 'Good'];
                }
            }
            return ['BIMI record not found in TXT records.', 'Bad'];
        }
        return ['No BIMI records found.', 'Bad'];
    }

    function check_zone_transfer($domain) {
        // Get NS records
        $ns_records = dns_get_record($domain, DNS_NS);
        if (!$ns_records) {
            return ['No NS records found.', 'Info'];
        }

        $results = [];
        foreach ($ns_records as $ns) {
            $nameserver = $ns['target'];
            // Try AXFR query using dig
            $output = [];
            $return_var = 0;
            exec("dig @{$nameserver} {$domain} AXFR +noall +answer", $output, $return_var);
            
            if (!empty($output)) {
                return ["Zone transfer possible from {$nameserver}!", 'Bad'];
            }
        }
        return ['Zone transfer not allowed', 'Good'];
    }

    function check_dnssec($domain) {
        // Check for DNSKEY records
        $dnskey_records = dns_get_record($domain, DNS_DNSKEY);
        
        // Check for DS records
        $ds_records = dns_get_record($domain, DNS_DS);
        
        if ($dnskey_records || $ds_records) {
            $details = [];
            if ($dnskey_records) {
                $details[] = "DNSKEY records found (" . count($dnskey_records) . ")";
            }
            if ($ds_records) {
                $details[] = "DS records found (" . count($ds_records) . ")";
            }
            return [implode(', ', $details), 'Good'];
        }
        
        return ['No DNSSEC records found', 'Bad'];
    }

    $results = [];
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['domain'])) {
        $domain = sanitize_domain($_POST['domain']);
        
        list($spf_result, $spf_rating) = check_spf($domain);
        list($dmarc_result, $dmarc_rating) = check_dmarc($domain);
        list($dkim_result, $dkim_rating) = check_dkim($domain);
        list($bimi_result, $bimi_rating) = check_bimi($domain);
        list($zone_result, $zone_rating) = check_zone_transfer($domain);
        list($dnssec_result, $dnssec_rating) = check_dnssec($domain);
        
        $results = [
            'domain' => $domain,
            'spf' => ['result' => $spf_result, 'rating' => $spf_rating],
            'dmarc' => ['result' => $dmarc_result, 'rating' => $dmarc_rating],
            'dkim' => ['result' => $dkim_result, 'rating' => $dkim_rating],
            'bimi' => ['result' => $bimi_result, 'rating' => $bimi_rating],
            'zone' => ['result' => $zone_result, 'rating' => $zone_rating],
            'dnssec' => ['result' => $dnssec_result, 'rating' => $dnssec_rating]
        ];
    }
    ?>

    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Domain Security Checker</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                margin: 20px; 
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
            }
            .good { color: green; font-weight: bold; }
            .bad { color: red; font-weight: bold; }
            .info { color: blue; font-weight: bold; }
            .result-box {
                border: 1px solid #ddd;
                padding: 15px;
                margin: 10px 0;
                border-radius: 4px;
                background-color: #f9f9f9;
            }
            .result-box strong {
                display: block;
                margin-bottom: 5px;
            }
            form {
                margin: 20px 0;
            }
            input[type="text"] {
                padding: 8px;
                width: 300px;
                margin-right: 10px;
            }
            button {
                padding: 8px 15px;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
            button:hover {
                background-color: #45a049;
            }
        </style>
    </head>
    <body>
        <div class="email-checker">
            <h2>Domain Security Checker</h2>
            <form method="post" action="">
                <label for="domain">Domain:</label>
                <input type="text" id="domain" name="domain" required placeholder="example.com" />
                <button type="submit">Check</button>
            </form>

            <?php if (!empty($results)): ?>
                <h3>Results for <?php echo htmlspecialchars($results['domain']); ?></h3>
                
                <div class="result-box">
                    <strong>SPF:</strong>
                    <span class="<?php echo strtolower($results['spf']['rating']); ?>">
                        (<?php echo htmlspecialchars($results['spf']['rating']); ?>)
                    </span>
                    <br>
                    <?php echo htmlspecialchars($results['spf']['result']); ?>
                </div>

                <div class="result-box">
                    <strong>DMARC:</strong>
                    <span class="<?php echo strtolower($results['dmarc']['rating']); ?>">
                        (<?php echo htmlspecialchars($results['dmarc']['rating']); ?>)
                    </span>
                    <br>
                    <?php echo htmlspecialchars($results['dmarc']['result']); ?>
                </div>

                <div class="result-box">
                    <strong>DKIM:</strong>
                    <span class="<?php echo strtolower($results['dkim']['rating']); ?>">
                        (<?php echo htmlspecialchars($results['dkim']['rating']); ?>)
                    </span>
                    <br>
                    <?php echo htmlspecialchars($results['dkim']['result']); ?>
                </div>

                <div class="result-box">
                    <strong>BIMI:</strong>
                    <span class="<?php echo strtolower($results['bimi']['rating']); ?>">
                        (<?php echo htmlspecialchars($results['bimi']['rating']); ?>)
                    </span>
                    <br>
                    <?php echo htmlspecialchars($results['bimi']['result']); ?>
                </div>

                <div class="result-box">
                    <strong>Zone Transfer:</strong>
                    <span class="<?php echo strtolower($results['zone']['rating']); ?>">
                        (<?php echo htmlspecialchars($results['zone']['rating']); ?>)
                    </span>
                    <br>
                    <?php echo htmlspecialchars($results['zone']['result']); ?>
                </div>

                <div class="result-box">
                    <strong>DNSSEC:</strong>
                    <span class="<?php echo strtolower($results['dnssec']['rating']); ?>">
                        (<?php echo htmlspecialchars($results['dnssec']['rating']); ?>)
                    </span>
                    <br>
                    <?php echo htmlspecialchars($results['dnssec']['result']); ?>
                </div>
            <?php endif; ?>
        </div>
    </body>
    </html>
