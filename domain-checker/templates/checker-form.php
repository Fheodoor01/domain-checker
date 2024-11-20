<?php
    // Prevent direct access
    if (!defined('ABSPATH')) {
        exit;
    }
    ?>
    <div class="domain-checker-container">
        <form id="domain-checker-form" class="domain-checker-form">
            <?php wp_nonce_field('domain_checker_nonce', 'domain_checker_nonce'); ?>
            <div class="form-group">
                <input type="text" 
                       id="domain" 
                       name="domain" 
                       class="domain-input" 
                       placeholder="<?php esc_attr_e('Enter domain (e.g., example.com)', 'domain-checker'); ?>" 
                       required>
                <button type="submit" class="check-button">
                    <?php esc_html_e('Check', 'domain-checker'); ?>
                </button>
            </div>
        </form>

        <div id="domain-checker-results" class="domain-checker-results" style="display: none;">
            <!-- Results will be inserted here via JavaScript -->
        </div>

        <div id="domain-checker-error" class="domain-checker-error" style="display: none;">
            <!-- Errors will be displayed here -->
        </div>
    </div>
