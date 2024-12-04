<?php
    return [
        'en' => [
            'title' => 'Immutec Domain Test',
            'enter_domain' => 'Enter domain (e.g., google.com)',
            'check_button' => 'Check',
            'overall_score' => 'Overall Score',
            'out_of_five' => 'out of 5',
            'summary' => 'Informational',
            'strengths' => 'Strengths',
            'improvements' => 'Improvements Needed',
            'risks_title' => 'Security Risks',
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
                'bimi' => 'BIMI',
                'https' => 'HTTPS Security'
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
                'bimi' => 'Brand Indicators for Message Identification (BIMI) allows you to display your logo next to authenticated emails.',
                'https' => 'HTTPS security ensures that data transmitted between your website and users is encrypted.'
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
                'implement_bimi' => 'Consider implementing BIMI to display your logo in emails',
                'configure_https' => 'Configure HTTPS to secure your website\'s data transmission',
                'spf_check' => 'SPF Check',
                'dmarc_check' => 'DMARC Check',
                'dkim_check' => 'DKIM Check',
                'reverse_dns_check' => 'Reverse DNS Check',
                'no_mx_records' => 'No MX records found',
                'missing_reverse_dns' => 'Missing reverse DNS for mail server %s (%s)',
                'reverse_dns_mismatch' => 'Forward-confirmed reverse DNS mismatch for %s (%s -> %s)',
                'valid_reverse_dns' => 'Valid reverse DNS for %s (%s -> %s)',
                'ip_resolve_error' => 'Could not resolve IP for mail server %s',
                'no_nameservers' => 'No nameservers found for your domain',
                'single_nameserver' => 'Only one nameserver found'
            ],
            'risks' => [
                'spf' => 'Emails could be spoofed from your domain',
                'dmarc' => 'Your domain is vulnerable to email spoofing',
                'dkim' => 'Emails may be marked as spam',
                'https' => 'Your website is not secure',
                'reverse_dns' => 'Mail servers may reject your emails',
                'no_nameservers' => 'No nameservers found for your domain'
            ],
            'improvements' => [
                'configure_spf' => 'Configure SPF to prevent email spoofing',
                'configure_dmarc' => 'Configure DMARC for better email security',
                'configure_dkim' => 'Configure DKIM to improve email deliverability',
                'configure_https' => 'Configure HTTPS to secure your website\'s data transmission',
                'configure_reverse_dns' => 'Configure reverse DNS for your mail servers',
                'configure_nameservers' => 'Configure nameservers for your domain',
                'add_nameserver' => 'Add additional nameserver for redundancy'
            ],
            'strengths' => [
                'spf_configured' => 'SPF is properly configured',
                'dmarc_configured' => 'DMARC is properly configured',
                'dkim_configured' => 'DKIM is properly configured',
                'https_configured' => 'HTTPS is properly configured',
                'reverse_dns_configured' => 'Reverse DNS is properly configured',
                'nameservers_redundant' => 'Multiple nameservers provide redundancy'
            ],
            'warnings' => [
                'https' => 'Website accessible over insecure HTTP without HTTPS redirect',
                'single_nameserver' => 'Only one nameserver found'
            ],
            'nameserver_messages' => [
                'no_nameservers' => 'No nameservers found for your domain',
                'single_nameserver' => 'Only one nameserver found',
                'nameservers_redundant' => 'Multiple nameservers provide redundancy'
            ]
        ],
        'nl' => [
            'title' => 'Immutec Domain Test',
            'enter_domain' => 'Voer domein in (bijv. google.com)',
            'check_button' => 'Controleer',
            'overall_score' => 'Totaalscore',
            'out_of_five' => 'out of 5',
            'summary' => 'Informatie',
            'strengths' => 'Sterke punten',
            'improvements' => 'Verbeterpunten',
            'risks_title' => 'Veiligheidsrisico\'s',
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
                'bimi' => 'BIMI',
                'https' => 'HTTPS Security'
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
                'bimi' => 'Brand Indicators for Message Identification (BIMI) maakt het mogelijk om uw logo naast geverifieerde e-mails weer te geven.',
                'https' => 'HTTPS security zorgt ervoor dat gegevensoverdracht tussen uw website en gebruikers wordt versleuteld.'
            ],
            'strength' => 'Sterkte',
            'messages' => [
                'spf_configured' => 'SPF is correct geconfigureerd',
                'dmarc_configured' => 'DMARC is correct geconfigureerd',
                'nameservers_redundant' => 'Meerdere nameservers zorgen voor goede redundantie',
                'dnssec_enabled' => 'DNSSEC is ingeschakeld, beschermt tegen DNS-spoofing',
                'tls_configured' => 'TLS is correct geconfigureerd voor e-mailbeveiliging',
                'implement_spf' => 'Implementeer SPF om e-mail vervalsing te voorkomen',
                'implement_dmarc' => 'Implementeer DMARC om e-mailverificatie te verbeteren',
                'enable_dnssec' => 'Schakel DNSSEC in om DNS-spoofing te voorkomen',
                'configure_tls' => 'Configureer TLS voor e-mailverzending',
                'implement_mta_sts' => 'Implementeer MTA-STS voor verbeterde mailbeveiliging',
                'implement_bimi' => 'Overweeg BIMI te implementeren om uw logo in e-mails weer te geven',
                'configure_https' => 'Configureer HTTPS om uw website\'s gegevensoverdracht te beveiligen',
                'spf_check' => 'SPF Controle',
                'dmarc_check' => 'DMARC Controle',
                'dkim_check' => 'DKIM Controle',
                'reverse_dns_check' => 'Reverse DNS Controle',
                'no_mx_records' => 'Geen MX records gevonden',
                'missing_reverse_dns' => 'Ontbrekende reverse DNS voor mailserver %s (%s)',
                'reverse_dns_mismatch' => 'Forward-confirmed reverse DNS mismatch voor %s (%s -> %s)',
                'valid_reverse_dns' => 'Geldige reverse DNS voor %s (%s -> %s)',
                'ip_resolve_error' => 'Kan IP niet oplossen voor mailserver %s',
                'no_nameservers' => 'Geen nameservers gevonden voor uw domein',
                'single_nameserver' => 'Slechts één nameserver gevonden'
            ],
            'risks' => [
                'spf' => 'E-mails kunnen worden vervalst vanaf uw domein',
                'dmarc' => 'Uw domein is kwetsbaar voor e-mail vervalsing',
                'dkim' => 'E-mails kunnen als spam worden gemarkeerd',
                'https' => 'Uw website is niet veilig',
                'reverse_dns' => 'Mailservers kunnen uw e-mails weigeren',
                'no_nameservers' => 'Geen nameservers gevonden voor uw domein'
            ],
            'improvements' => [
                'configure_spf' => 'Configureer SPF om e-mail vervalsing te voorkomen',
                'configure_dmarc' => 'Configureer DMARC voor betere e-mailbeveiliging',
                'configure_dkim' => 'Configureer DKIM om e-mail bezorging te verbeteren',
                'configure_https' => 'Configureer HTTPS om uw website\'s gegevensoverdracht te beveiligen',
                'configure_reverse_dns' => 'Configureer reverse DNS voor uw mailservers',
                'configure_nameservers' => 'Configureer nameservers voor uw domein',
                'add_nameserver' => 'Voeg extra nameserver toe voor redundantie'
            ],
            'strengths' => [
                'spf_configured' => 'SPF is correct geconfigureerd',
                'dmarc_configured' => 'DMARC is correct geconfigureerd',
                'dkim_configured' => 'DKIM is correct geconfigureerd',
                'https_configured' => 'HTTPS is correct geconfigureerd',
                'reverse_dns_configured' => 'Reverse DNS is correct geconfigureerd',
                'nameservers_redundant' => 'Meerdere nameservers zorgen voor redundantie'
            ],
            'warnings' => [
                'https' => 'Website toegankelijk via onveilig HTTP zonder HTTPS-doorverwijzing',
                'single_nameserver' => 'Slechts één nameserver gevonden'
            ],
            'nameserver_messages' => [
                'no_nameservers' => 'Geen nameservers gevonden voor uw domein',
                'single_nameserver' => 'Slechts één nameserver gevonden',
                'nameservers_redundant' => 'Meerdere nameservers zorgen voor redundantie'
            ]
        ]
    ];
    ?>
