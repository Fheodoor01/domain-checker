<?php
    return [
        'dns' => [
            'timeout' => 5,
            'retry' => 3,
            'dkim_selectors' => ['default', 'google', 'selector1', 'selector2', 'dkim', 'mail']
        ],
        'explanations' => [
            'nameservers' => 'Name servers are responsible for hosting your domain\'s DNS records. Multiple name servers provide redundancy.',
            'smtp' => 'SMTP servers handle email delivery for your domain. They should be properly configured and accessible.',
            'dnssec' => 'DNSSEC adds cryptographic signatures to DNS records to prevent tampering and DNS spoofing.',
            'spf' => 'SPF specifies which mail servers are authorized to send email on behalf of your domain.',
            'dmarc' => 'DMARC tells receiving servers what to do with emails that fail SPF or DKIM checks.',
            'dane' => 'DANE allows you to bind X.509 certificates to DNS names using DNSSEC.',
            'tls' => 'TLS encryption secures email transmission between mail servers.',
            'tls_report' => 'TLS reporting provides feedback about TLS connection successes and failures.',
            'mta_sts' => 'MTA-STS is a mechanism enabling mail service providers to declare their ability to receive TLS-secured connections.'
        ]
    ];
    ?>
