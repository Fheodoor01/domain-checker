<?php
    error_reporting(E_ALL);
    ini_set('display_errors', 1);

    require_once 'check.php';
    $config = require 'config.php';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Debug information
        error_log("POST received");
        error_log("POST data: " . print_r($_POST, true));
        error_log("Raw input: " . file_get_contents('php://input'));
        
        $domain = $_POST['domain'] ?? '';
        
        if (empty($domain)) {
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false, 
                'error' => 'Domain is empty',
                'debug' => [
                    'post' => $_POST,
                    'raw_input' => file_get_contents('php://input')
                ]
            ]);
            exit;
        }

        try {
            $checker = new DomainChecker($config);
            $results = $checker->checkAll($domain);
            
            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'data' => $results,
                'debug' => [
                    'domain' => $domain,
                    'post' => $_POST
                ]
            ]);
        } catch (Exception $e) {
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage(),
                'debug' => [
                    'domain' => $domain,
                    'post' => $_POST
                ]
            ]);
        }
        exit;
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
                <form id="checkForm" class="mb-6">
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
                
                <div id="results" class="hidden space-y-4">
                </div>
                
                <div id="error" class="hidden text-red-500 p-4">
                </div>
                
                <div id="debug" class="mt-4 p-4 bg-gray-100 rounded">
                    <h3 class="font-bold">Debug Output:</h3>
                    <pre id="debugOutput"></pre>
                </div>
            </div>
        </div>

        <script>
        document.getElementById('checkForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const domain = document.getElementById('domain').value.trim();
            const results = document.getElementById('results');
            const error = document.getElementById('error');
            const debugOutput = document.getElementById('debugOutput');
            
            if (!domain) {
                error.textContent = 'Please enter a domain';
                error.classList.remove('hidden');
                results.classList.add('hidden');
                return;
            }
            
            results.innerHTML = '<div class="text-center p-4">Checking...</div>';
            results.classList.remove('hidden');
            error.classList.add('hidden');
            
            try {
                debugOutput.textContent = `Sending request for domain: ${domain}\n`;
                
                // Use URLSearchParams for the request
                const params = new URLSearchParams();
                params.append('domain', domain);
                
                debugOutput.textContent += `Request params: ${params.toString()}\n`;
                
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: params
                });
                
                debugOutput.textContent += 'Response received\n';
                
                const data = await response.json();
                debugOutput.textContent += 'Response data: ' + JSON.stringify(data, null, 2);
                
                if (data.success) {
                    results.innerHTML = formatResults(data.data);
                } else {
                    throw new Error(data.error || 'An error occurred');
                }
            } catch (err) {
                error.textContent = err.message || 'An error occurred while checking the domain.';
                error.classList.remove('hidden');
                results.classList.add('hidden');
                debugOutput.textContent += '\nError: ' + err.message;
            }
        });

        function formatResults(data) {
            // ... (rest of the formatResults function remains the same)
        }
        </script>
    </body>
    </html>
