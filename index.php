<?php
    error_reporting(E_ALL);
    ini_set('display_errors', 1);

    require_once 'check.php';
    $config = require 'config.php';

    $results = null;
    $error = null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
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
            case 'warning':
                return 'text-yellow-600';
            default:
                return 'text-gray-600';
        }
    }

    function getStatusText($status) {
        switch (strtolower($status)) {
            case 'good':
                return 'Passed';
            case 'bad':
                return 'Failed';
            case 'warning':
                return 'Warning';
            default:
                return 'Unknown';
        }
    }

    function generateSummary($results) {
        $strengths = [];
        $improvements = [];
        $risks = [];

        // Check each component and build the summary
        foreach ($results as $key => $result) {
            if ($key === 'overall_score') continue;

            switch ($result['status']) {
                case 'good':
                    switch ($key) {
                        case 'spf':
                            $strengths[] = "SPF is properly configured" . 
                                (isset($result['strength']) ? " with {$result['strength']} policy" : "");
                            break;
                        case 'dmarc':
                            $strengths[] = "DMARC is properly configured" . 
                                (isset($result['strength']) ? " with {$result['strength']} policy" : "");
                            break;
                        case 'nameservers':
                            $strengths[] = "Multiple nameservers provide good redundancy";
                            break;
                        case 'dnssec':
                            $strengths[] = "DNSSEC is enabled, protecting against DNS spoofing";
                            break;
                        case 'tls':
                            $strengths[] = "TLS is properly configured for email security";
                            break;
                        default:
                            $strengths[] = ucfirst($key) . " is properly configured";
                    }
                    break;

                case 'bad':
                    switch ($key) {
                        case 'spf':
                            $improvements[] = "Implement SPF to prevent email spoofing";
                            $risks[] = "Emails could be spoofed from your domain";
                            break;
                        case 'dmarc':
                            $improvements[] = "Implement DMARC to improve email authentication";
                            $risks[] = "No policy for handling failed email authentication";
                            break;
                        case 'dnssec':
                            $improvements[] = "Enable DNSSEC to prevent DNS spoofing";
                            $risks[] = "Vulnerable to DNS spoofing attacks";
                            break;
                        case 'tls':
                            $improvements[] = "Configure TLS for email transmission";
                            $risks[] = "Emails might be transmitted without encryption";
                            break;
                        case 'mta_sts':
                            $improvements[] = "Implement MTA-STS for improved mail security";
                            break;
                        case 'bimi':
                            $improvements[] = "Consider implementing BIMI to display your logo in emails";
                            break;
                        default:
                            $improvements[] = "Configure " . ucfirst($key);
                    }
                    break;

                case 'warning':
                    $improvements[] = "Improve " . ucfirst($key) . " configuration";
                    break;
            }
        }

        return [
            'strengths' => $strengths,
            'improvements' => $improvements,
            'risks' => $risks
        ];
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Domain Test</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100">
        <div class="container mx-auto px-4 py-8">
            <h1 class="text-3xl font-bold mb-8">Domain Test</h1>
            
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
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                        <!-- Score -->
                        <div class="text-center bg-gray-50 rounded-lg p-6">
                            <h2 class="text-2xl font-bold mb-2">Overall Score</h2>
                            <p class="text-4xl font-bold <?php echo $results['overall_score'] >= 4 ? 'text-green-600' : 'text-yellow-600'; ?>">
                                <?php echo $results['overall_score']; ?>/5
                            </p>
                        </div>

                        <!-- Summary -->
                        <?php $summary = generateSummary($results); ?>
                        <div class="bg-gray-50 rounded-lg p-6">
                            <h2 class="text-2xl font-bold mb-4">Summary</h2>
                            
                            <?php if (!empty($summary['strengths'])): ?>
                                <div class="mb-4">
                                    <h3 class="text-green-600 font-bold mb-2">Strengths:</h3>
                                    <ul class="list-disc list-inside text-sm">
                                        <?php foreach ($summary['strengths'] as $strength): ?>
                                            <li><?php echo htmlspecialchars($strength); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>

                            <?php if (!empty($summary['improvements'])): ?>
                                <div class="mb-4">
                                    <h3 class="text-yellow-600 font-bold mb-2">Improvements Needed:</h3>
                                    <ul class="list-disc list-inside text-sm">
                                        <?php foreach ($summary['improvements'] as $improvement): ?>
                                            <li><?php echo htmlspecialchars($improvement); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>

                            <?php if (!empty($summary['risks'])): ?>
                                <div>
                                    <h3 class="text-red-600 font-bold mb-2">Security Risks:</h3>
                                    <ul class="list-disc list-inside text-sm">
                                        <?php foreach ($summary['risks'] as $risk): ?>
                                            <li><?php echo htmlspecialchars($risk); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Detailed Results -->
                    <div class="space-y-4">
                        <?php
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

                        foreach ($checks as $key => $title):
                            if (isset($results[$key])):
                        ?>
                            <div class="border rounded-lg p-4 bg-gray-50">
                                <div class="flex justify-between items-center mb-2">
                                    <h3 class="font-bold text-lg"><?php echo htmlspecialchars($title); ?></h3>
                                    <span class="<?php echo getStatusColor($results[$key]['status']); ?> font-bold">
                                        <?php echo htmlspecialchars(getStatusText($results[$key]['status'])); ?>
                                    </span>
                                </div>

                                <p class="text-gray-600 text-sm mb-2">
                                    <?php echo htmlspecialchars($config['explanations'][$key]); ?>
                                </p>

                                <?php if (isset($results[$key]['message'])): ?>
                                    <p class="mt-2">
                                        <?php echo htmlspecialchars($results[$key]['message']); ?>
                                    </p>
                                <?php endif; ?>

                                <?php if (isset($results[$key]['record'])): ?>
                                    <p class="font-mono text-sm bg-gray-100 p-2 rounded mt-2 break-all">
                                        <?php echo htmlspecialchars($results[$key]['record']); ?>
                                    </p>
                                <?php endif; ?>

                                <?php if (isset($results[$key]['records']) && is_array($results[$key]['records'])): ?>
                                    <div class="mt-2">
                                        <?php foreach ($results[$key]['records'] as $record): ?>
                                            <p class="font-mono text-sm bg-gray-100 p-2 rounded mt-1">
                                                <?php 
                                                if (is_array($record)) {
                                                    echo htmlspecialchars("Priority: {$record['priority']}, Host: {$record['host']}");
                                                } else {
                                                    echo htmlspecialchars($record);
                                                }
                                                ?>
                                            </p>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>

                                <?php if (isset($results[$key]['strength'])): ?>
                                    <p class="mt-2">
                                        <span class="font-semibold">Strength:</span>
                                        <span class="font-bold">
                                            <?php echo htmlspecialchars(strtoupper($results[$key]['strength'])); ?>
                                        </span>
                                    </p>
                                <?php endif; ?>
                            </div>
                        <?php 
                            endif;
                        endforeach; 
                        ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </body>
    </html>
