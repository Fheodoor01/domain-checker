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
        $risks = [];

        foreach ($results as $key => $result) {
            if ($key === 'overall_score') continue;

            switch ($result['status']) {
                case 'good':
                    $message = $lang['messages'][$key . '_configured'] ?? ucfirst($key) . ' ' . $lang['status']['passed'];
                    if (isset($result['strength'])) {
                        $message .= " ({$result['strength']})";
                    }
                    $strengths[] = $message;
                    break;

                case 'bad':
                    $message = $lang['messages']['implement_' . $key] ?? ucfirst($key) . ' ' . $lang['status']['failed'];
                    $improvements[] = [
                        'message' => $message,
                        'key' => $key
                    ];
                    break;

                case 'warning':
                    $message = $lang['messages']['improve_' . $key] ?? $lang['messages']['generic_improve'];
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
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
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

                <?php if ($error): ?>
                    <div class="text-red-500 p-4 mb-4 bg-red-50 rounded">
                        <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <?php if ($results): ?>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                        <!-- Score -->
                        <div class="text-center bg-gray-50 rounded-lg p-6">
                            <h2 class="text-2xl font-bold mb-2"><?php echo $lang['overall_score']; ?></h2>
                            <p class="text-4xl font-bold <?php echo $results['overall_score'] >= 4 ? 'text-green-600' : 'text-yellow-600'; ?>">
                                <?php echo $results['overall_score']; ?>/5
                            </p>
                        </div>

                        <!-- Summary -->
                        <?php $summary = generateSummary($results, $lang); ?>
                        <div class="bg-gray-50 rounded-lg p-6">
                            <h2 class="text-2xl font-bold mb-4"><?php echo $lang['summary']; ?></h2>
                            
                            <?php if (!empty($summary['strengths'])): ?>
                                <div class="mb-4">
                                    <h3 class="text-green-600 font-bold mb-2"><?php echo $lang['strengths']; ?>:</h3>
                                    <ul class="list-disc list-inside text-sm">
                                        <?php foreach ($summary['strengths'] as $strength): ?>
                                            <li><?php echo htmlspecialchars($strength); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>

                            <?php if (!empty($summary['improvements'])): ?>
                                <div class="mb-4">
                                    <h3 class="text-yellow-600 font-bold mb-2"><?php echo $lang['improvements']; ?>:</h3>
                                    <ul class="list-disc list-inside text-sm">
                                        <?php foreach ($summary['improvements'] as $improvement): ?>
                                            <li class="mb-2">
                                                <?php echo htmlspecialchars($improvement['message']); ?>
                                                <?php if (isset($lang['risks'][$improvement['key']])): ?>
                                                    <div class="text-red-600 text-xs ml-5 mt-1">
                                                        <?php echo htmlspecialchars($lang['risks'][$improvement['key']]); ?>
                                                    </div>
                                                <?php endif; ?>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Detailed Results -->
                    <div class="space-y-4">
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
                <?php endif; ?>
            </div>
        </div>
    </body>
    </html>
