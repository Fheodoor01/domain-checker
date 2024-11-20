jQuery(document).ready(function($) {
        const form = $('#domain-checker-form');
        const results = $('#domain-checker-results');
        const error = $('#domain-checker-error');

        form.on('submit', function(e) {
            e.preventDefault();
            
            const domain = $('#domain').val().trim();
            if (!domain) {
                showError(domainCheckerStrings.enterDomain);
                return;
            }

            // Show loading state
            results.html('<div class="loading">' + domainCheckerStrings.checking + '</div>').show();
            error.hide();

            // Perform AJAX request
            $.ajax({
                url: domainCheckerAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'check_domain',
                    nonce: domainCheckerAjax.nonce,
                    domain: domain
                },
                success: function(response) {
                    if (response.success) {
                        displayResults(response.data);
                    } else {
                        showError(response.data);
                    }
                },
                error: function() {
                    showError(domainCheckerStrings.errorOccurred);
                }
            });
        });

        function displayResults(data) {
            let html = '<div class="results-container">';
            
            // Overall Score
            html += `
                <div class="score-section">
                    <h2>${domainCheckerStrings.overallScore}</h2>
                    <p class="${data.overall_score >= 4 ? 'status-good' : 'status-warning'}">
                        ${data.overall_score}/5
                    </p>
                </div>
            `;

            // Summary Section
            html += '<div class="summary-section">';
            
            // Strengths
            if (data.strengths && data.strengths.length > 0) {
                html += `
                    <div class="strengths-section">
                        <h3 class="section-title">${domainCheckerStrings.strengths}</h3>
                        <ul>
                            ${data.strengths.map(strength => `<li>${escapeHtml(strength)}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }

            // Improvements
            if (data.improvements && data.improvements.length > 0) {
                html += `
                    <div class="improvements-section">
                        <h3 class="section-title">${domainCheckerStrings.improvements}</h3>
                        <ul>
                            ${data.improvements.map(improvement => `<li>${escapeHtml(improvement.message)}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }

            // Security Risks
            if (data.risks && data.risks.length > 0) {
                html += `
                    <div class="risks-section">
                        <h3 class="section-title">${domainCheckerStrings.securityRisks}</h3>
                        <ul>
                            ${data.risks.map(risk => `<li>${escapeHtml(risk)}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }

            html += '</div>'; // End summary section

            // Detailed Results
            html += '<div class="detailed-results">';
            for (const [key, value] of Object.entries(data)) {
                if (key === 'overall_score' || key === 'strengths' || key === 'improvements' || key === 'risks') continue;

                html += `
                    <div class="result-section">
                        <div class="result-header">
                            <h3>${escapeHtml(key)}</h3>
                            <span class="status-${value.status}">${escapeHtml(value.status)}</span>
                        </div>
                        ${value.message ? `<p>${escapeHtml(value.message)}</p>` : ''}
                        ${value.record ? `<div class="record-details">${escapeHtml(value.record)}</div>` : ''}
                        ${value.strength ? `<p class="strength">Strength: ${escapeHtml(value.strength)}</p>` : ''}
                    </div>
                `;
            }
            html += '</div>'; // End detailed results

            html += '</div>'; // End results container
            
            results.html(html).show();
        }

        function showError(message) {
            error.html(escapeHtml(message)).show();
            results.hide();
        }

        function escapeHtml(unsafe) {
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
    });
