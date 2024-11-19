<?php
    require_once 'check.php';
    $config = require 'config.php';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        try {
            $domain = filter_var($_POST['domain'], FILTER_SANITIZE_URL);
            if (!$domain) {
                throw new Exception('Invalid domain');
            }
            
            // Remove any protocol prefixes and trailing slashes
            $domain = preg_replace('#^https?://#', '', $domain);
            $domain = trim($domain, '/');
            
            // Basic domain validation
            if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$/', $domain)) {
                throw new Exception('Invalid domain format');
            }
            
            $checker = new DomainChecker($config);
            $results = $checker->checkAll($domain);
            
            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'data' => $results
            ]);
            
        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
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
                               placeholder="Enter domain (e.g., example.com)" 
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
            </div>
        </div>

        <script>
        document.getElementById('checkForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const domain = document.getElementById('domain').value;
            const results = document.getElementById('results');
            const error = document.getElementById('error');
            
            results.innerHTML = '<div class="text-center p-4">Checking...</div>';
            results.classList.remove('hidden');
            error.classList.add('hidden');
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `domain=${encodeURIComponent(domain)}`
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.error || 'An error occurred');
                }
                
                if (data.success) {
                    results.innerHTML = formatResults(data.data);
                } else {
                    throw new Error(data.error || 'An error occurred');
                }
            } catch (err) {
                error.textContent = err.message || 'An error occurred while checking the domain.';
                error.classList.remove('hidden');
                results.classList.add('hidden');
            }
        });

        function formatResults(data) {
            const sections = {
                spf: 'SPF (Sender Policy Framework)',
                dmarc: 'DMARC (Domain-based Message Authentication)',
                dkim: 'DKIM (DomainKeys Identified Mail)',
                bimi: 'BIMI (Brand Indicators for Message Identification)',
                zone_transfer: 'Zone Transfer',
                dnssec: 'DNSSEC'
            };

            return Object.entries(data).map(([key, value]) => {
                const title = sections[key];
                const status = value.status || 'unknown';
                const message = value.message || '';
                const record = value.record || '';
                const strength = value.strength || '';

                const statusColor = {
                    good: 'text-green-600',
                    bad: 'text-red-600',
                    error: 'text-yellow-600'
                }[status];

                let content = `
                    <div class="border rounded-lg p-4 bg-gray-50">
                        <h3 class="font-bold text-lg mb-2">${title}</h3>
                        <div class="space-y-2">
                            <p>
                                <span class="font-semibold">Status:</span> 
                                <span class="${statusColor}">${status.toUpperCase()}</span>
                            </p>`;

                if (strength) {
                    content += `
                        <p>
                            <span class="font-semibold">Strength:</span> 
                            <span>${strength.toUpperCase()}</span>
                        </p>`;
                }

                if (message) {
                    content += `
                        <p>
                            <span class="font-semibold">Message:</span> 
                            <span>${message}</span>
                        </p>`;
                }

                if (record) {
                    content += `
                        <p class="font-mono text-sm bg-gray-100 p-2 rounded overflow-x-auto">
                            ${record}
                        </p>`;
                }

                // Handle DKIM special case (multiple selectors)
                if (key === 'dkim' && typeof value === 'object') {
                    content += `<div class="mt-2">`;
                    for (const [selector, selectorData] of Object.entries(value)) {
                        content += `
                            <div class="mt-2 p-2 bg-gray-100 rounded">
                                <p class="font-semibold">Selector: ${selector}</p>
                                <p>Status: <span class="${statusColor}">${selectorData.status.toUpperCase()}</span></p>
                                ${selectorData.record ? `<p class="font-mono text-sm mt-1">${selectorData.record}</p>` : ''}
                                ${selectorData.message ? `<p class="mt-1">${selectorData.message}</p>` : ''}
                            </div>`;
                    }
                    content += `</div>`;
                }

                content += `
                        </div>
                    </div>`;

                return content;
            }).join('');
        }
        </script>
    </body>
    </html>
