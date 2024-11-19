<?php
    error_reporting(E_ALL);
    ini_set('display_errors', 1);

    require_once 'check.php';
    $config = require 'config.php';

    $results = null;
    $error = null;
    $debug = [];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $debug['post_data'] = $_POST;
        $domain = $_POST['domain'] ?? '';
        
        if (empty($domain)) {
            $error = 'Please enter a domain';
        } else {
            try {
                $checker = new DomainChecker($config);
                $results = $checker->checkAll($domain);
            } catch (Exception $e) {
                $error = $e->getMessage();
            }
        }
    }

    function getStatusColor($status) {
        switch (strtolower($status)) {
            case 'good':
                return 'text-green-600';
            case 'bad':
                return 'text-red-600';
            case 'info':
                return 'text-blue-600';
            default:
                return 'text-yellow-600';
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Domain Security Checker</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <style>
            .record-box {
                word-break: break-word;
                overflow-wrap: break-word;
            }
        </style>
    </head>
    <body class="bg-gray-100">
        <div class="container mx-auto px-4 py-8">
            <h1 class="text-3xl font-bold mb-8">Domain Security Checker</h1>
            
            <div class="bg-white rounded-lg shadow p-6">
                <form method="post" class="mb-6">
                    <div class="flex gap-4">
                        <input type="text" 
                               id="domain" 
                               name="domain" 
                               class="flex-1 p-2 border rounded" 
                               placeholder="Enter domain (e.g., google.com)" 
                               value="<?php echo htmlspecialchars($_POST['domain'] ?? ''); ?>"
                               required>
                        <button type="submit" 
                                class="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
                            Check
                        </button>
                    </div>
                </form>
                
                <?php if ($error): ?>
                    <div class="text-red-500 p-4 mb-4 bg-red-50 rounded">
                        <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <?php if ($results): ?>
                    <div class="space-y-4">
                        <!-- SPF -->
                        <div class="border rounded-lg p-4 bg-gray-50">
                            <h3 class="font-bold text-lg mb-2">SPF (Sender Policy Framework)</h3>
                            <div class="space-y-2">
                                <p>
                                    <span class="font-semibold">Status:</span>
                                    <span class="<?php echo getStatusColor($results['spf']['status']); ?> font-bold">
                                        <?php echo htmlspecialchars(strtoupper($results['spf']['status'])); ?>
                                    </span>
                                </p>
                                <?php if (isset($results['spf']['strength'])): ?>
                                    <p>
                                        <span class="font-semibold">Strength:</span>
                                        <span class="font-bold">
                                            <?php echo htmlspecialchars(strtoupper($results['spf']['strength'])); ?>
                                        </span>
                                    </p>
                                <?php endif; ?>
                                <?php if (isset($results['spf']['record'])): ?>
                                    <p class="font-mono text-sm bg-gray-100 p-2 rounded record-box">
                                        <?php echo htmlspecialchars($results['spf']['record']); ?>
                                    </p>
                                <?php endif; ?>
                            </div>
                        </div>

                        <!-- DMARC -->
                        <div class="border rounded-lg p-4 bg-gray-50">
                            <h3 class="font-bold text-lg mb-2">DMARC (Domain-based Message Authentication)</h3>
                            <div class="space-y-2">
                                <p>
                                    <span class="font-semibold">Status:</span>
                                    <span class="<?php echo getStatusColor($results['dmarc']['status']); ?> font-bold">
                                        <?php echo htmlspecialchars(strtoupper($results['dmarc']['status'])); ?>
                                    </span>
                                </p>
                                <?php if (isset($results['dmarc']['strength'])): ?>
                                    <p>
                                        <span class="font-semibold">Strength:</span>
                                        <span class="font-bold">
                                            <?php echo htmlspecialchars(strtoupper($results['dmarc']['strength'])); ?>
                                        </span>
                                    </p>
                                <?php endif; ?>
                                <?php if (isset($results['dmarc']['record'])): ?>
                                    <p class="font-mono text-sm bg-gray-100 p-2 rounded record-box">
                                        <?php echo htmlspecialchars($results['dmarc']['record']); ?>
                                    </p>
                                <?php endif; ?>
                            </div>
                        </div>

                        <!-- DKIM -->
                        <div class="border rounded-lg p-4 bg-gray-50">
                            <h3 class="font-bold text-lg mb-2">DKIM (DomainKeys Identified Mail)</h3>
                            <div class="space-y-2">
                                <?php
                                $hasValidDkim = false;
                                foreach ($results['dkim'] as $selector => $data):
                                    if ($data['status'] === 'good'):
                                        $hasValidDkim = true;
                                ?>
                                    <div class="p-2 bg-gray-100 rounded mb-2">
                                        <p class="font-semibold">Selector: <?php echo htmlspecialchars($selector); ?></p>
                                        <p>
                                            <span class="font-semibold">Status:</span>
                                            <span class="<?php echo getStatusColor($data['status']); ?> font-bold">
                                                <?php echo htmlspecialchars(strtoupper($data['status'])); ?>
                                            </span>
                                        </p>
                                        <?php if (isset($data['record'])): ?>
                                            <p class="font-mono text-sm mt-1 record-box">
                                                <?php echo htmlspecialchars($data['record']); ?>
                                            </p>
                                        <?php endif; ?>
                                    </div>
                                <?php 
                                    endif;
                                endforeach;
                                
                                if (!$hasValidDkim): ?>
                                    <p>
                                        <span class="font-semibold">Status:</span>
                                        <span class="text-red-600 font-bold">BAD</span>
                                    </p>
                                    <p>No valid DKIM record found</p>
                                <?php endif; ?>
                            </div>
                        </div>

                        <!-- BIMI -->
                        <div class="border rounded-lg p-4 bg-gray-50">
                            <h3 class="font-bold text-lg mb-2">BIMI (Brand Indicators for Message Identification)</h3>
                            <div class="space-y-2">
                                <p>
                                    <span class="font-semibold">Status:</span>
                                    <span class="<?php echo getStatusColor($results['bimi']['status']); ?> font-bold">
                                        <?php echo htmlspecialchars(strtoupper($results['bimi']['status'])); ?>
                                    </span>
                                </p>
                                <?php if (isset($results['bimi']['message'])): ?>
                                    <p>
                                        <span class="font-semibold">Message:</span>
                                        <?php echo htmlspecialchars($results['bimi']['message']); ?>
                                    </p>
                                <?php endif; ?>
                                <?php if (isset($results['bimi']['record'])): ?>
                                    <p class="font-mono text-sm bg-gray-100 p-2 rounded record-box">
                                        <?php echo htmlspecialchars($results['bimi']['record']); ?>
                                    </p>
                                <?php endif; ?>
                            </div>
                        </div>

                        <!-- Zone Transfer -->
                        <div class="border rounded-lg p-4 bg-gray-50">
                            <h3 class="font-bold text-lg mb-2">Zone Transfer</h3>
                            <div class="space-y-2">
                                <p>
                                    <span class="font-semibold">Status:</span>
                                    <span class="<?php echo getStatusColor($results['zone_transfer']['status']); ?> font-bold">
                                        <?php echo htmlspecialchars(strtoupper($results['zone_transfer']['status'])); ?>
                                    </span>
                                </p>
                                <?php if (isset($results['zone_transfer']['message'])): ?>
                                    <p>
                                        <span class="font-semibold">Message:</span>
                                        <?php echo htmlspecialchars($results['zone_transfer']['message']); ?>
                                    </p>
                                <?php endif; ?>
                            </div>
                        </div>

                        <!-- DNSSEC -->
                        <div class="border rounded-lg p-4 bg-gray-50">
                            <h3 class="font-bold text-lg mb-2">DNSSEC</h3>
                            <div class="space-y-2">
                                <p>
                                    <span class="font-semibold">Status:</span>
                                    <span class="<?php echo getStatusColor($results['dnssec']['status']); ?> font-bold">
                                        <?php echo htmlspecialchars(strtoupper($results['dnssec']['status'])); ?>
                                    </span>
                                </p>
                                <?php if (isset($results['dnssec']['message'])): ?>
                                    <p>
                                        <span class="font-semibold">Message:</span>
                                        <?php echo htmlspecialchars($results['dnssec']['message']); ?>
                                    </p>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

                <?php if ($debug): ?>
                    <div class="mt-4 p-4 bg-gray-100 rounded">
                        <h3 class="font-bold">Debug Output:</h3>
                        <pre class="mt-2 text-sm"><?php echo htmlspecialchars(print_r($debug, true)); ?></pre>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </body>
    </html>
