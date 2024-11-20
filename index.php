<?php
    // Only update the title and checks array in your existing index.php
    // Find this line in your <title> tag:
    // <title>Email Security Checker</title>
    // And replace it with:
    // <title>Domain Test</title>

    // Find this line in your <h1> tag:
    // <h1 class="text-3xl font-bold mb-8">Email Security Checker</h1>
    // And replace it with:
    // <h1 class="text-3xl font-bold mb-8">Domain Test</h1>

    // Update your existing $checks array to include BIMI:
    $checks = [
        'nameservers' => 'Name Servers',
        'smtp' => 'SMTP Servers',
        'dnssec' => 'DNSSEC',
        'spf' => 'SPF',
        'dmarc' => 'DMARC',
        'dane' => 'DANE',
        'tls' => 'TLS',
        'tls_report' => 'TLS Report',
        'mta_sts' => 'MTA-STS',
        'bimi' => 'BIMI'
    ];
    ?>
