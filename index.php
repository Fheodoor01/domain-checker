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
        $domain = $_POST['domain'] ?? '';
        
        if (empty($domain)) {
            $error = 'Please enter a domain';
        } else {
            try {
                $checker = new \DomainChecker\DomainChecker($config);
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
        $improvements = [];

        foreach ($results as $key => $result) {
            if ($key === 'overall_score' || $key === 'debug') continue;

            switch ($result['status']) {
                case 'good':
                    $message = isset($lang['messages'][$key . '_configured']) ? 
                              $lang['messages'][$key . '_configured'] : 
                              ucfirst($key) . ' ' . $lang['status']['passed'];
                    if (isset($result['strength'])) {
                        $message .= " ({$result['strength']})";
                    }
                    $strengths[] = $message;
                    break;

                case 'bad':
                    $message = isset($lang['messages']['implement_' . $key]) ? 
                              $lang['messages']['implement_' . $key] : 
                              ucfirst($key) . ' ' . $lang['status']['failed'];
                    $improvements[] = [
                        'message' => $message,
                        'key' => $key
                    ];
                    break;

                case 'warning':
                    $message = isset($lang['messages']['improve_' . $key]) ? 
                              $lang['messages']['improve_' . $key] : 
                              ucfirst($key) . ' ' . $lang['status']['warning'];
                    $improvements[] = [
                        'message' => $message,
                        'key' => $key
                    ];
                    break;
            }
        }

        return [
            'strengths' => $strengths,
            'improvements' => $improvements
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
            .loading-animation {
                display: none;
                justify-content: center;
                align-items: center;
                margin: 2rem 0;
            }

            .shield-spinner {
                width: 60px;
                height: 60px;
                position: relative;
                animation: shield-pulse 1.5s ease-in-out infinite;
            }

            .shield-spinner:before {
                content: '';
                position: absolute;
                width: 100%;
                height: 100%;
                border-radius: 50%;
                border: 3px solid #4f46e5;
                border-top-color: transparent;
                animation: shield-spin 1s linear infinite;
            }

            .shield-spinner:after {
                content: '🛡️';
                font-size: 24px;
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
            }

            @keyframes shield-spin {
                to {
                    transform: rotate(360deg);
                }
            }

            @keyframes shield-pulse {
                0% {
                    transform: scale(1);
                }
                50% {
                    transform: scale(1.1);
                }
                100% {
                    transform: scale(1);
                }
            }

            .results-container {
                transition: opacity 0.3s ease-in-out;
            }
        </style>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const domainInput = document.getElementById('domain');
                const form = document.querySelector('form');
                const loadingAnimation = document.querySelector('.loading-animation');

                function hideAllResults() {
                    const elements = document.querySelectorAll('.results-section, .grid, .bg-red-100, [class*="rounded-lg p-6"]');
                    elements.forEach(element => {
                        if (element.parentElement && !element.closest('form')) {
                            element.style.display = 'none';
                        }
                    });
                }

                function animateScore(finalScore) {
                    const scoreElement = document.querySelector('.score-value');
                    const scoreImage = document.querySelector('.score-image');
                    const images = ['score_poor.png', 'score_fair.png', 'score_good.png', 'score_excellent.png'];
                    let currentStep = 0;
                    const steps = 10; // Number of steps in animation
                    const duration = 500; // Animation duration in milliseconds
                    const stepDuration = duration / steps;

                    function updateScoreDisplay(score, imageIndex) {
                        if (scoreElement) {
                            scoreElement.textContent = score.toFixed(2) + '/5';
                            if (scoreImage) {
                                scoreImage.src = 'images/' + images[imageIndex % images.length];
                            }
                        }
                    }

                    const interval = setInterval(() => {
                        currentStep++;
                        const progress = currentStep / steps;
                        const currentScore = (progress * finalScore) + (Math.random() * 0.5);
                        const imageIndex = Math.floor(Math.random() * images.length);
                        
                        updateScoreDisplay(Math.min(currentScore, 5), imageIndex);

                        if (currentStep >= steps) {
                            clearInterval(interval);
                            updateScoreDisplay(finalScore, getImageIndexForScore(finalScore * 20));
                        }
                    }, stepDuration);
                }

                function getImageIndexForScore(score) {
                    if (score >= 90) return 3; // excellent
                    if (score >= 70) return 2; // good
                    if (score >= 50) return 1; // fair
                    return 0; // poor
                }

                // Clear results when typing in domain input
                domainInput?.addEventListener('input', hideAllResults);

                // Show loading animation when form is submitted
                form?.addEventListener('submit', function() {
                    hideAllResults();
                    if (loadingAnimation) {
                        loadingAnimation.style.display = 'flex';
                    }
                });

                // Start animation when results are shown
                const observer = new MutationObserver((mutations) => {
                    mutations.forEach((mutation) => {
                        if (mutation.addedNodes.length) {
                            mutation.addedNodes.forEach((node) => {
                                if (node.classList && node.classList.contains('grid')) {
                                    const scoreText = document.querySelector('.score-value');
                                    if (scoreText) {
                                        const finalScore = parseFloat(scoreText.textContent);
                                        animateScore(finalScore);
                                    }
                                }
                            });
                        }
                    });
                });

                observer.observe(document.body, { childList: true, subtree: true });
            });
        </script>
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
                    <div class="flex gap-4">
                        <input type="text" 
                               id="domain" 
                               name="domain" 
                               class="flex-1 p-2 border rounded" 
                               placeholder="<?php echo $lang['enter_domain']; ?>" 
                               value="<?php echo htmlspecialchars($_POST['domain'] ?? ''); ?>"
                               required>
                        <button type="submit" 
                                class="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
                            <?php echo $lang['check_button']; ?>
                        </button>
                    </div>
                </form>

                <!-- Loading Animation -->
                <div class="loading-animation">
                    <div class="shield-spinner"></div>
                </div>

                <?php if ($error): ?>
                    <div class="text-red-500 p-4 mb-4 bg-red-50 rounded">
                        <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <?php if ($results): ?>
                    <?php if (is_string($results)): ?>
                        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4">
                            <strong class="font-bold"><?php echo $results; ?></strong>
                        </div>
                    <?php else: ?>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
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
                            <p class="text-4xl font-bold <?php echo $class; ?> mb-4">
                                <span class="score-value"><?php echo $displayScore; ?></span>/5
                            </p>
                            <img src="images/<?php echo $scoreImage; ?>" alt="Score Rating" class="h-64 mx-auto score-image">
                        </div>

                        <!-- Summary -->
                        <?php $summary = generateSummary($results, $lang); ?>
                        <div class="bg-gray-50 rounded-lg p-6">
                            <h2 class="text-2xl font-bold mb-4"><?php echo $lang['summary']; ?></h2>
                            
                            <?php if (!empty($summary['strengths'])): ?>
                                <div class="mb-4">
                                    <h3 class="text-green-600 font-bold mb-2"><?php echo ucfirst($lang['strengths']); ?>:</h3>
                                    <ul class="list-disc list-inside text-sm">
                                        <?php foreach ($summary['strengths'] as $strength): ?>
                                            <li><?php echo ucfirst(trim(htmlspecialchars($strength))); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>

                            <?php if (!empty($summary['improvements'])): ?>
                                <div>
                                    <h3 class="text-red-600 font-bold mb-2"><?php echo ucfirst($lang['improvements']); ?>:</h3>
                                    <ul class="list-disc list-inside text-sm">
                                        <?php foreach ($summary['improvements'] as $improvement): ?>
                                            <li><?php echo ucfirst(trim(htmlspecialchars($improvement['message']))); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>

                                <!-- Security Risks Section -->
                                <div>
                                    <h3 class="text-red-600 font-bold mb-2">Security Risks:</h3>
                                    <ul class="list-disc list-inside text-sm">
                                        <?php 
                                        $shown_risks = [];
                                        foreach ($summary['improvements'] as $improvement):
                                            $key = $improvement['key'];
                                            if (isset($lang['risks'][$key]) && !in_array($lang['risks'][$key], $shown_risks)):
                                                $shown_risks[] = $lang['risks'][$key];
                                        ?>
                                            <li class="text-red-600">
                                                <?php echo htmlspecialchars($lang['risks'][$key]); ?>
                                            </li>
                                        <?php 
                                            endif;
                                        endforeach; 
                                        ?>
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
    </html>
