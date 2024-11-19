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
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Domain Security Checker</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
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
                               required>
                        <button type="submit" 
                                class="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
                            Check
                        </button>
                    </div>
                </form>
                
                <?php if ($error): ?>
                    <div class="text-red-500 p-4">
                        <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <?php if ($results): ?>
                    <div class="space-y-4">
                        <?php foreach ($results as $key => $value): ?>
                            <div class="border rounded-lg p-4 bg-gray-50">
                                <h3 class="font-bold text-lg mb-2">
                                    <?php
                                    $titles = [
                                        'spf' => 'SPF (Sender Policy Framework)',
                                        'dmarc' => 'DMARC (Domain-based Message Authentication)',
                                        'dkim' => 'DKIM (DomainKeys Identified Mail)',
                                        'bimi' => 'BIMI (Brand Indicators for Message Identification)',
                                        'zone_transfer' => 'Zone Transfer',
                                        'dnssec' => 'DNSSEC'
                                    ];
                                    echo htmlspecialchars($titles[$key] ?? $key);
                                    ?>
                                </h3>
                                <div class="space-y-2">
                                    <p>
                                        <span class="font-semibold">Status:</span>
                                        <span class="<?php echo $value['status'] === 'good' ? 'text-green-600' : 'text-red-600'; ?>">
                                            <?php echo htmlspecialchars(strtoupper($value['status'] ?? 'unknown')); ?>
                                        </span>
                                    </p>
                                    
                                    <?php if (!empty($value['strength'])): ?>
                                        <p>
                                            <span class="font-semibold">Strength:</span>
                                            <span><?php echo htmlspecialchars(strtoupper($value['strength'])); ?></span>
                                        </p>
                                    <?php endif; ?>

                                    <?php if (!empty($value['message'])): ?>
                                        <p>
                                            <span class="font-semibold">Message:</span>
                                            <span><?php echo htmlspecialchars($value['message']); ?></span>
                                        </p>
                                    <?php endif; ?>

                                    <?php if (!empty($value['record'])): ?>
                                        <p class="font-mono text-sm bg-gray-100 p-2 rounded overflow-x-auto">
                                            <?php echo htmlspecialchars($value['record']); ?>
                                        </p>
                                    <?php endif; ?>

                                    <?php if ($key === 'dkim' && is_array($value)): ?>
                                        <div class="mt-2">
                                            <?php foreach ($value as $selector => $selectorData): ?>
                                                <div class="mt-2 p-2 bg-gray-100 rounded">
                                                    <p class="font-semibold">Selector: <?php echo htmlspecialchars($selector); ?></p>
                                                    <p>Status: 
                                                        <span class="<?php echo $selectorData['status'] === 'good' ? 'text-green-600' : 'text-red-600'; ?>">
                                                            <?php echo htmlspecialchars(strtoupper($selectorData['status'])); ?>
                                                        </span>
                                                    </p>
                                                    <?php if (!empty($selectorData['record'])): ?>
                                                        <p class="font-mono text-sm mt-1">
                                                            <?php echo htmlspecialchars($selectorData['record']); ?>
                                                        </p>
                                                    <?php endif; ?>
                                                    <?php if (!empty($selectorData['message'])): ?>
                                                        <p class="mt-1">
                                                            <?php echo htmlspecialchars($selectorData['message']); ?>
                                                        </p>
                                                    <?php endif; ?>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <div class="mt-4 p-4 bg-gray-100 rounded">
                    <h3 class="font-bold">Debug Output:</h3>
                    <pre><?php echo htmlspecialchars(print_r($debug, true)); ?></pre>
                </div>
            </div>
        </div>
    </body>
    </html>
