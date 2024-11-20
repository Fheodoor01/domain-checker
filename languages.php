<?php
    return [
        'en' => [
            'title' => 'Domain Test',
            'enter_domain' => 'Enter domain (e.g., google.com)',
            'check_button' => 'Check',
            'overall_score' => 'Overall Score',
            'summary' => 'Summary',
            'strengths' => 'Strengths',
            'improvements' => 'Improvements Needed',
            'risks' => 'Security Risks',
            'status' => [
                'passed' => 'Passed',
                'failed' => 'Failed',
                'warning' => 'Warning',
                'unknown' => 'Unknown'
            ],
            'sections' => [
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
                'mta_sts' => 'MTA-STS is a mechanism enabling mail service providers to declare their ability to receive TLS-secured connections.',
                'bimi' => 'Brand Indicators for Message Identification (BIMI) allows you to display your logo next to authenticated emails.'
            ],
            'strength' => 'Strength',
            'messages' => [
                'spf_configured' => 'SPF is properly configured',
                'dmarc_configured' => 'DMARC is properly configured',
                'nameservers_redundant' => 'Multiple nameservers provide good redundancy',
                'dnssec_enabled' => 'DNSSEC is enabled, protecting against DNS spoofing',
                'tls_configured' => 'TLS is properly configured for email security',
                'implement_spf' => 'Implement SPF to prevent email spoofing',
                'implement_dmarc' => 'Implement DMARC to improve email authentication',
                'enable_dnssec' => 'Enable DNSSEC to prevent DNS spoofing',
                'configure_tls' => 'Configure TLS for email transmission',
                'implement_mta_sts' => 'Implement MTA-STS for improved mail security',
                'implement_bimi' => 'Consider implementing BIMI to display your logo in emails'
            ],
            'risks' => [
                'email_spoofing' => 'Emails could be spoofed from your domain',
                'no_auth_policy' => 'No policy for handling failed email authentication',
                'dns_spoofing' => 'Vulnerable to DNS spoofing attacks',
                'unencrypted_email' => 'Emails might be transmitted without encryption'
            ]
        ],
        'nl' => [
            'title' => 'Domein Test',
            'enter_domain' => 'Voer domein in (bijv. google.com)',
            'check_button' => 'Controleer',
            'overall_score' => 'Totaalscore',
            'summary' => 'Samenvatting',
            'strengths' => 'Sterke punten',
            'improvements' => 'Verbeterpunten',
            'risks' => 'Veiligheidsrisico\'s',
            'status' => [
                'passed' => 'Geslaagd',
                'failed' => 'Mislukt',
                'warning' => 'Waarschuwing',
                'unknown' => 'Onbekend'
            ],
            'sections' => [
                'nameservers' => 'Nameservers',
                'smtp' => 'SMTP Servers',
                'dnssec' => 'DNSSEC',
                'spf' => 'SPF',
                'dmarc' => 'DMARC',
                'dane' => 'DANE',
                'tls' => 'TLS',
                'tls_report' => 'TLS Rapportage',
                'mta_sts' => 'MTA-STS',
                'bimi' => 'BIMI'
            ],
            'explanations' => [
                'nameservers' => 'Nameservers zijn verantwoordelijk voor het hosten van de DNS-records van uw domein. Meerdere nameservers zorgen voor redundantie.',
                'smtp' => 'SMTP-servers verwerken e-mailbezorging voor uw domein. Deze moeten correct geconfigureerd en toegankelijk zijn.',
                'dnssec' => 'DNSSEC voegt cryptografische handtekeningen toe aan DNS-records om manipulatie en DNS-spoofing te voorkomen.',
                'spf' => 'SPF specificeert welke mailservers gemachtigd zijn om e-mail te verzenden namens uw domein.',
                'dmarc' => 'DMARC vertelt ontvangende servers wat te doen met e-mails die niet slagen voor SPF- of DKIM-controles.',
                'dane' => 'DANE maakt het mogelijk om X.509-certificaten te koppelen aan DNS-namen met behulp van DNSSEC.',
                'tls' => 'TLS-encryptie beveiligt e-mailverzending tussen mailservers.',
                'tls_report' => 'TLS-rapportage geeft feedback over successen en mislukkingen van TLS-verbindingen.',
                'mta_sts' => 'MTA-STS is een mechanisme waarmee e-mailproviders hun mogelijkheid om TLS-beveiligde verbindingen te ontvangen kunnen declareren.',
                'bimi' => 'Brand Indicators for Message Identification (BIMI) maakt het mogelijk om uw logo naast geverifieerde e-mails weer te geven.'
            ],
            'strength' => 'Sterkte',
            'messages' => [
                'spf_configured' => 'SPF is correct geconfigureerd',
                'dmarc_configured' => 'DMARC is correct geconfigureerd',
                'nameservers_redundant' => 'Meerdere nameservers zorgen voor goede redundantie',
                'dnssec_enabled' => 'DNSSEC is ingeschakeld, beschermt tegen DNS-spoofing',
                'tls_configured' => 'TLS is correct geconfigureerd voor e-mailbeveiliging',
                'implement_spf' => 'Implementeer SPF om e-mail spoofing te voorkomen',
                'implement_dmarc' => 'Implementeer DMARC om e-mailverificatie te verbeteren',
                'enable_dnssec' => 'Schakel DNSSEC in om DNS-spoofing te voorkomen',
                'configure_tls' => 'Configureer TLS voor e-mailverzending',
                'implement_mta_sts' => 'Implementeer MTA-STS voor verbeterde mailbeveiliging',
                'implement_bimi' => 'Overweeg BIMI te implementeren om uw logo in e-mails weer te geven'
            ],
            'risks' => [
                'email_spoofing' => 'E-mails kunnen worden vervalst vanaf uw domein',
                'no_auth_policy' => 'Geen beleid voor het afhandelen van mislukte e-mailverificatie',
                'dns_spoofing' => 'Kwetsbaar voor DNS-spoofing aanvallen',
                'unencrypted_email' => 'E-mails kunnen zonder encryptie worden verzonden'
            ]
        ]
    ];
    ?>
