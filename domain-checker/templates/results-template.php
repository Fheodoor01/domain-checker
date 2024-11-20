<?php
    if (!defined('ABSPATH')) {
        exit;
    }
    ?>
    <script type="text/html" id="tmpl-domain-checker-results">
        <div class="results-container">
            <!-- Overall Score -->
            <div class="score-section">
                <h2><?php esc_html_e('Overall Score', 'domain-checker'); ?></h2>
                <p class="<# if (data.overall_score >= 4) { #>status-good<# } else { #>status-warning<# } #>">
                    {{data.overall_score}}/5
                </p>
            </div>

            <!-- Summary -->
            <div class="summary-section">
                <# if (data.strengths && data.strengths.length > 0) { #>
                    <div class="strengths-section">
                        <h3 class="section-title"><?php esc_html_e('Strengths', 'domain-checker'); ?></h3>
                        <ul>
                            <# _.each(data.strengths, function(strength) { #>
                                <li>{{strength}}</li>
                            <# }); #>
                        </ul>
                    </div>
                <# } #>

                <# if (data.improvements && data.improvements.length > 0) { #>
                    <div class="improvements-section">
                        <h3 class="section-title"><?php esc_html_e('Improvements Needed', 'domain-checker'); ?></h3>
                        <ul>
                            <# _.each(data.improvements, function(improvement) { #>
                                <li>{{improvement.message}}</li>
                            <# }); #>
                        </ul>
                    </div>
                <# } #>

                <# if (data.risks && data.risks.length > 0) { #>
                    <div class="risks-section">
                        <h3 class="section-title"><?php esc_html_e('Security Risks', 'domain-checker'); ?></h3>
                        <ul>
                            <# _.each(data.risks, function(risk) { #>
                                <li>{{risk}}</li>
                            <# }); #>
                        </ul>
                    </div>
                <# } #>
            </div>
        </div>
    </script>
