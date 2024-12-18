<?php
    error_reporting(E_ALL);
    ini_set('display_errors', 1);

    require_once 'check.php';
    require_once 'language_detector.php';
    $config = require 'config.php';
    $languages = require 'languages.php';

    // Get current language
    $currentLang = detectLanguage();
    $lang = $languages[$currentLang];

    $results = null;
    $error = null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $domain = $_POST['domain'] ?? null;
        
        if ($domain) {
            try {
                $checker = new \DomainChecker\DomainChecker($config);
                $results = $checker->checkAll($domain);
                
                if ($results === false || (is_array($results) && empty($results))) {
                    echo '<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">';
                    echo '<strong class="font-bold">Error: </strong>';
                    echo '<span class="block sm:inline">Domain is not valid. Please check your input and try again.</span>';
                    echo '</div>';
                    $results = null;
                }
            } catch (Exception $e) {
                echo '<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">';
                echo '<strong class="font-bold">Error: </strong>';
                echo '<span class="block sm:inline">Domain is not valid. Please check your input and try again.</span>';
                echo '</div>';
                $results = null;
            }
        } else {
            echo '<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">';
            echo '<strong class="font-bold">Error: </strong>';
            echo '<span class="block sm:inline">Please enter a domain.</span>';
            echo '</div>';
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

    function getStatusText($status, $lang) {
        switch (strtolower($status)) {
            case 'good':
                return $lang['status']['passed'];
            case 'bad':
                return $lang['status']['failed'];
            case 'warning':
                return $lang['status']['warning'];
            default:
                return $lang['status']['unknown'];
        }
    }

    function generateSummary($results, $lang) {
        $strengths = [];
        $services = [];

        foreach ($results as $key => $result) {
            if ($key === 'overall_score' || $key === 'debug' || $key === 'detected_services') continue;

            switch ($result['status'] ?? 'unknown') {
                case 'good':
                    $message = isset($lang['messages'][$key . '_configured']) ? 
                              $lang['messages'][$key . '_configured'] : 
                              ucfirst($key) . ' ' . $lang['status']['passed'];
                    if (isset($result['strength'])) {
                        $message .= " ({$result['strength']})";
                    }
                    $strengths[] = $message;
                    break;
            }
        }

        // Process detected services
        if (isset($results['detected_services']) && !empty($results['detected_services'])) {
            foreach ($results['detected_services'] as $service) {
                $serviceInfo = $service['name'];
                if (isset($service['description'])) {
                    $serviceInfo .= " - {$service['description']}";
                }
                if (isset($service['type'])) {
                    $serviceInfo .= " ({$service['type']})";
                }
                $services[] = $serviceInfo;
            }
        }

        return [
            'strengths' => $strengths,
            'services' => $services
        ];
    }
    ?>
    <!DOCTYPE html>
    <html lang="<?php echo $currentLang; ?>">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?php echo $lang['title']; ?></title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            header {
                background: #003366;
                color: #fff;
                padding: 15px 20px;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }
            header a {
                display: flex;
                align-items: center;
                height: 40px;
            }
            header img {
                height: 100%;
                width: auto;
                object-fit: contain;
            }
            nav ul {
                list-style: none;
                padding: 0;
                margin: 0;
                display: flex;
            }
            nav ul li {
                margin-left: 20px;
            }
            nav ul li a {
                text-decoration: none;
                color: white;
            }
            .loading-animation {
                position: fixed;
                inset: 0;
                background: rgba(255, 255, 255, 0.8);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 50;
            }

            .shield-spinner {
                position: relative;
                width: 168px;
                height: 168px;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto;
            }

            .shield-image {
                width: auto;
                height: 70%;
                position: relative;
                z-index: 2;
                animation: breathe 2s ease-in-out infinite;
                object-fit: contain;
            }

            .spinner-ring {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                border: 10.4px solid rgba(0, 0, 0, 0.1);
                border-top-color: #3498db;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }

            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            @keyframes breathe {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.05); }
            }

            .input-container {
                flex: 1;
            }

            /* Hide scrollbar for Chrome, Safari and Opera */
            .no-scrollbar::-webkit-scrollbar {
                display: none;
            }

            /* Hide scrollbar for IE, Edge and Firefox */
            .no-scrollbar {
                -ms-overflow-style: none;  /* IE and Edge */
                scrollbar-width: none;  /* Firefox */
            }
        </style>
        <link rel="stylesheet" href="assets/css/styles.css">
        <script src="assets/js/main.js" defer></script>
        <style>
            .debug-section pre {
                white-space: pre-wrap;
                word-wrap: break-word;
            }
        </style>
    </head>
    <body class="bg-gray-100">
    <header>
        <a href="https://immutec.eu/">
            <img src="https://immutec.eu/wp-content/uploads/2024/04/logo_IMMUTEC_tagline_diap.png" alt="Immutec Logo">
        </a>
    </header>
        <div class="container mx-auto px-4 py-8">
            <!-- Language Selector -->
            <div class="flex justify-end mb-6">
                <div class="flex gap-2">
                    <a href="?lang=en" class="<?php echo $currentLang === 'en' ? 'font-bold underline' : ''; ?>">EN</a>
                    <span>|</span>
                    <a href="?lang=nl" class="<?php echo $currentLang === 'nl' ? 'font-bold underline' : ''; ?>">NL</a>
                </div>
            </div>

            <h1 class="text-3xl font-bold mb-8"><?php echo $lang['title']; ?></h1>
            
            <div class="bg-white rounded-lg shadow p-6">
                <form method="post" class="mb-6">
                    <div class="flex flex-col gap-4">
                        <div class="flex gap-4">
                            <div class="input-container">
                                <input type="text" 
                                    id="domain" 
                                    name="domain" 
                                    class="w-full p-2 border rounded" 
                                    placeholder="<?php echo $lang['enter_domain']; ?>" 
                                    value="<?php echo htmlspecialchars($_POST['domain'] ?? ''); ?>"
                                    required>
                                <div id="domain-error" class="domain-error"></div>
                            </div>
                            <button type="submit" 
                                    class="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed">
                                <?php echo $lang['check_button']; ?>
                            </button>
                        </div>
                    </div>
                </form>

                <!-- Loading Animation -->
                <div class="loading-animation hidden">
                    <div class="bg-white rounded-lg p-8 flex flex-col items-center">
                        <div class="shield-spinner">
                            <div class="spinner-ring"></div>
                            <img src="images/shield.png" alt="Loading" class="shield-image">
                        </div>
                        <p class="mt-4 text-lg font-semibold text-center" id="loading-text">Checking domain...</p>
                    </div>
                </div>

                <?php if ($error): ?>
                    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
                        <strong class="font-bold">Error: </strong>
                        <span class="block sm:inline"><?php echo htmlspecialchars($error); ?></span>
                    </div>
                <?php endif; ?>

                <?php if ($results): ?>
                    <?php if (is_string($results)): ?>
                        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
                            <strong class="font-bold">Error: </strong>
                            <span class="block sm:inline">Domain is not valid. Please check your input and try again.</span>
                        </div>
                    <?php else: ?>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                        <!-- Score -->
                        <div class="text-center bg-gray-50 rounded-lg p-6">
                            <h2 class="text-2xl font-bold mb-2"><?php echo $lang['overall_score']; ?></h2>
                            <?php
                                $score = $results['overall_score'] * 20;
                                $scoreImage = '';
                                if ($score >= 90) {
                                    $class = 'text-green-600';
                                    $scoreImage = 'score_excellent.png';
                                } elseif ($score >= 70) {
                                    $class = 'text-green-500';
                                    $scoreImage = 'score_good.png';
                                } elseif ($score >= 50) {
                                    $class = 'text-yellow-600';
                                    $scoreImage = 'score_fair.png';
                                } else {
                                    $class = 'text-red-600';
                                    $scoreImage = 'score_poor.png';
                                }
                                
                                // Format score to remove decimal places if it's a whole number
                                $displayScore = is_numeric($results['overall_score']) ? 
                                    (floor($results['overall_score']) == $results['overall_score'] ? 
                                        number_format($results['overall_score'], 0) : 
                                        number_format($results['overall_score'], 2)) : 
                                    $results['overall_score'];
                            ?>
                            <div id="score-display" class="relative">
                                <div class="text-3xl font-bold mb-4 <?php echo $class; ?>">
                                    <span class="score-value"><?php echo $displayScore; ?></span>/5
                                </div>
                                <div class="relative w-72 h-72 mx-auto rounded-full bg-white shadow-lg p-4">
                                    <img src="images/<?php echo $scoreImage; ?>" alt="Score Rating" class="w-full h-full object-contain score-image">
                                </div>
                            </div>
                        </div>

                        <!-- Risks -->
                        <div class="bg-gray-50 rounded-lg p-6">
                            <h2 class="text-2xl font-bold mb-4"><?php echo isset($lang['risks_title']) ? htmlspecialchars($lang['risks_title']) : 'Security Risks'; ?></h2>
                            <?php
                            $risks = [];
                            $riskClassifications = [
                                'spf' => ['type' => 'Email Security', 'severity' => 'Critical'],
                                'dmarc' => ['type' => 'Email Security', 'severity' => 'Critical'],
                                'dnssec' => ['type' => 'DNS Security', 'severity' => 'Severe'],
                                'tls' => ['type' => 'Transport Security', 'severity' => 'High'],
                                'mta_sts' => ['type' => 'Email Security', 'severity' => 'Moderate'],
                                'dane' => ['type' => 'Transport Security', 'severity' => 'High']
                            ];
                            
                            if (is_array($results)) {
                                foreach ($results as $key => $section) {
                                    if (!is_string($key) || !isset($lang['risks'][$key])) {
                                        continue;
                                    }
                                    
                                    // Add both 'bad' and 'warning' status for HTTPS checks
                                    if (is_array($section) && isset($section['status']) && 
                                        ($section['status'] === 'bad' || 
                                        ($key === 'https' && $section['status'] === 'warning'))) {
                                        
                                        $riskInfo = $riskClassifications[$key] ?? ['type' => 'General Security', 'severity' => 'Moderate'];
                                        
                                        // Adjust severity for HTTPS warnings
                                        if ($key === 'https' && $section['status'] === 'warning') {
                                            $riskInfo['severity'] = 'Moderate';
                                        }
                                        
                                        $message = '';
                                        if (isset($section['message'])) {
                                            $message = is_array($section['message']) ? json_encode($section['message']) : (string)$section['message'];
                                        }
                                        
                                        // Get the appropriate risk description based on status for HTTPS
                                        $description = '';
                                        if ($key === 'https' && is_array($lang['risks'][$key])) {
                                            $description = ($section['status'] === 'warning') 
                                                ? (string)$lang['risks'][$key]['warning'] 
                                                : (string)$lang['risks'][$key]['bad'];
                                        } else {
                                            $description = isset($lang['risks'][$key]) ? (string)$lang['risks'][$key] : '';
                                        }
                                        
                                        $risks[] = [
                                            'title' => isset($lang['sections'][$key]) ? (string)$lang['sections'][$key] : (string)$key,
                                            'message' => $message,
                                            'description' => $description,
                                            'classification' => (string)$riskInfo['type'],
                                            'severity' => (string)$riskInfo['severity']
                                        ];
                                    }
                                }
                            }
                            $riskCount = count($risks);

                            // Function to get severity color classes
                            function getSeverityClasses($severity) {
                                switch ($severity) {
                                    case 'Critical':
                                        return ['bg-red-200 text-red-900', 'bg-red-100'];
                                    case 'Severe':
                                        return ['bg-orange-200 text-orange-900', 'bg-orange-100'];
                                    case 'High':
                                        return ['bg-yellow-200 text-yellow-900', 'bg-yellow-100'];
                                    case 'Moderate':
                                        return ['bg-blue-200 text-blue-900', 'bg-blue-100'];
                                    default:
                                        return ['bg-gray-200 text-gray-900', 'bg-gray-100'];
                                }
                            }
                            ?>
                            <div class="text-center mb-4">
                                <div class="text-6xl font-bold <?php echo $riskCount > 0 ? 'text-red-600' : 'text-green-600'; ?> mb-2">
                                    <?php echo $riskCount; ?>
                                </div>
                                <p class="text-gray-600"><?php echo $lang['risks_found'] ?? 'Security risks found'; ?></p>
                            </div>
                            <?php if ($riskCount > 0): ?>
                                <div class="mt-4 space-y-3">
                                    <?php foreach ($risks as $risk): 
                                        $severityClasses = getSeverityClasses($risk['severity']);
                                    ?>
                                        <div class="bg-red-50 p-3 rounded-lg">
                                            <div class="flex justify-between items-start mb-2">
                                                <h4 class="font-bold text-red-700"><?php echo htmlspecialchars($risk['title']); ?></h4>
                                                <div class="flex gap-2">
                                                    <span class="text-xs px-2 py-1 <?php echo $severityClasses[0]; ?> rounded">
                                                        <?php echo htmlspecialchars($risk['severity']); ?>
                                                    </span>
                                                    <span class="text-xs px-2 py-1 bg-gray-200 text-gray-800 rounded">
                                                        <?php echo htmlspecialchars($risk['classification']); ?>
                                                    </span>
                                                </div>
                                            </div>
                                            <?php if (!empty($risk['message'])): ?>
                                                <p class="text-sm text-red-600 mb-2"><?php echo htmlspecialchars($risk['message']); ?></p>
                                            <?php endif; ?>
                                            <p class="text-sm text-red-800 <?php echo $severityClasses[1]; ?> p-2 rounded">
                                                <strong>Security Risk:</strong> <?php echo htmlspecialchars($risk['description']); ?>
                                            </p>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>

                        <!-- Summary -->
                        <?php $summary = generateSummary($results, $lang); ?>
                        <div class="bg-gray-50 rounded-lg p-6">
                            <h2 class="text-2xl font-bold mb-6"><?php echo ucfirst($lang['summary']); ?></h2>
                            
                            <?php if (!empty($summary['services'])): ?>
                                <div class="mb-6">
                                    <h3 class="text-lg font-semibold mb-2"><?php echo $lang['detected_services'] ?? 'Detected Services'; ?></h3>
                                    <ul class="list-disc list-inside space-y-2">
                                        <?php foreach ($summary['services'] as $service): ?>
                                            <li class="text-blue-800"><?php echo htmlspecialchars($service); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>

                            <?php if (!empty($summary['strengths'])): ?>
                                <div class="mb-6">
                                    <h3 class="text-lg font-semibold mb-2"><?php echo $lang['strengths']; ?></h3>
                                    <ul class="list-disc list-inside space-y-2">
                                        <?php foreach ($summary['strengths'] as $strength): ?>
                                            <li class="text-green-600"><?php echo htmlspecialchars($strength); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Detailed Results -->
                    <div class="space-y-4 results-section">
                        <?php foreach ($lang['sections'] as $key => $title):
                            if (isset($results[$key])):
                        ?>
                            <div class="border rounded-lg p-4 bg-gray-50">
                                <div class="flex justify-between items-center mb-2">
                                    <h3 class="font-bold text-lg"><?php echo htmlspecialchars($title); ?></h3>
                                    <span class="<?php echo getStatusColor($results[$key]['status']); ?> font-bold">
                                        <?php echo htmlspecialchars(getStatusText($results[$key]['status'], $lang)); ?>
                                    </span>
                                </div>

                                <p class="text-gray-600 text-sm mb-2">
                                    <?php echo htmlspecialchars($lang['explanations'][$key]); ?>
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
                                        <span class="font-semibold"><?php echo $lang['strength']; ?>:</span>
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

                    <!-- Debug Information -->
                    <?php if (isset($results['debug']) && !empty($results['debug'])): ?>
                        <div class="mt-8 p-4 bg-gray-50 rounded-lg debug-section">
                            <h2 class="text-xl font-bold mb-4">Debug Information</h2>
                            <?php foreach ($results['debug'] as $debug): ?>
                                <div class="mb-4 p-2 bg-gray-100 rounded">
                                    <p class="font-bold"><?php echo htmlspecialchars($debug['check']); ?> - <?php echo htmlspecialchars($debug['time']); ?></p>
                                    <p class="text-sm"><?php echo htmlspecialchars($debug['message']); ?></p>
                                    <?php if (isset($debug['data']) && !empty($debug['data'])): ?>
                                        <pre class="text-xs mt-2 bg-gray-200 p-2 rounded">
                                            <?php echo htmlspecialchars(print_r($debug['data'], true)); ?>
                                        </pre>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            <?php endif; ?>
            </div>
        </div>
    </body>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const testNameInterval = 350;
            const minimumLoadingTime = 2500;
            let testNameIndex = 0;
            const testNames = ["Nameservers", "SMTP", "DNSSEC", "SPF", "DMARC", "DANE", "TLS", "TLS Report", "MTA-STS", "BIMI", "HTTPS", "Reverse DNS", "CAA", "DDoS Protection"];

            function cycleTestNames() {
                const testNameElement = document.getElementById('loading-text');
                if (testNameElement) {
                    testNameElement.textContent = `Checking ${testNames[testNameIndex]}...`;
                    testNameIndex = (testNameIndex + 1) % testNames.length;
                }
            }

            // Start cycling test names
            const testNameCycling = setInterval(cycleTestNames, testNameInterval);

            // Wait for at least 2.5 seconds before showing results
            setTimeout(() => {
                clearInterval(testNameCycling);
                document.querySelector('.loading-animation').classList.add('hidden');
            }, minimumLoadingTime);
        });
    </script>
    </html>
