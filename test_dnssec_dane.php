<?php

require_once 'netdns2-masterNet/DNS2.php';

function queryDnsServer($domain, $type, $dnsServer) {
    $resolver = new Net_DNS2_Resolver([
        'nameservers' => [$dnsServer],
        'dnssec' => true
    ]);

    try {
        $response = $resolver->query($domain, $type);
        return $response;
    } catch (Net_DNS2_Exception $e) {
        echo "Error querying DNS server: " . $e->getMessage() . "\n";
        return null;
    }
}

function testDnssec($domain, $dnsServer) {
    echo "Testing DNSSEC for: $domain\n";
    $response = queryDnsServer($domain, 'RRSIG', $dnsServer);

    if ($response && !empty($response->answer)) {
        echo "DNSSEC is enabled. RRSIG records found:\n";
        foreach ($response->answer as $record) {
            echo $record . "\n";
        }
    } else {
        echo "DNSSEC is not enabled or no RRSIG records found.\n";
    }
}

function testDane($domain, $dnsServer) {
    echo "Testing DANE for: $domain\n";
    $ports = [25, 465, 587];
    foreach ($ports as $port) {
        $tlsaDomain = sprintf('_%d._tcp.%s', $port, $domain);
        $response = queryDnsServer($tlsaDomain, 'TLSA', $dnsServer);

        if ($response && !empty($response->answer)) {
            echo "DANE is enabled on port $port. TLSA records found:\n";
            foreach ($response->answer as $record) {
                echo $record . "\n";
            }
        } else {
            echo "No TLSA records found on port $port.\n";
        }
    }
}

$domain = 'immutec.eu';
$dnsServer = '8.8.8.8'; // Google's public DNS server

testDnssec($domain, $dnsServer);
testDane($domain, $dnsServer);
