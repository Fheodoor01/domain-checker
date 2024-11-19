<?php
    // ... (previous code remains the same until checkDkim function)

    private function checkDkim($domain) {
        foreach ($this->config['dns']['dkim_selectors'] as $selector) {
            try {
                $records = dns_get_record($selector . '._domainkey.' . $domain, DNS_TXT);
                if ($records) {
                    foreach ($records as $record) {
                        if (isset($record['txt']) && strpos($record['txt'], 'v=DKIM1') === 0) {
                            // Return immediately when we find a valid DKIM record
                            return [
                                'status' => 'good',
                                'selector' => $selector,
                                'record' => $record['txt']
                            ];
                        }
                    }
                }
            } catch (Exception $e) {
                continue; // Try next selector if this one fails
            }
        }
        // Return bad status if no valid DKIM record is found
        return [
            'status' => 'bad',
            'message' => 'No valid DKIM record found'
        ];
    }

    // ... (rest of the code remains the same)
    ?>
