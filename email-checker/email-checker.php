<?php
    /*
    Plugin Name: Email Checker
    Description: A plugin to check SPF, DMARC, DKIM, and BIMI records for a given domain.
    Version: 1.0
    Author: Bolt
    */

    if (!defined('ABSPATH')) {
        exit; // Exit if accessed directly
    }

    function email_checker_menu() {
        add_options_page(
            'Email Checker',
            'Email Checker',
            'manage_options',
            'email-checker',
            'email_checker_settings_page'
        );
    }
    add_action('admin_menu', 'email_checker_menu');

    function email_checker_settings_page() {
        ?>
        <div class="wrap">
            <h1>Email Checker</h1>
            <form method="post" action="">
                <?php wp_nonce_field('email_checker_nonce_action', 'email_checker_nonce'); ?>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Domain</th>
                        <td><input type="text" name="domain" value="<?php echo esc_attr(get_option('email_checker_domain')); ?>" /></td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <?php
            if (isset($_POST['domain']) && check_admin_referer('email_checker_nonce_action', 'email_checker_nonce')) {
                $domain = sanitize_text_field($_POST['domain']);
                update_option('email_checker_domain', $domain);

                list($spf_result, $spf_rating) = email_checker_check_spf($domain);
                list($dmarc_result, $dmarc_rating) = email_checker_check_dmarc($domain);
                list($dkim_result, $dkim_rating) = email_checker_check_dkim($domain, 'default'); // Assuming default selector
                list($bimi_result, $bimi_rating) = email_checker_check_bimi($domain);

                echo '<h2>Results for ' . esc_html($domain) . '</h2>';
                echo '<p><strong>SPF:</strong> ' . esc_html($spf_result) . ' <span style="color: ' . ($spf_rating == 'Good' ? 'green' : 'red') . ';">(' . esc_html($spf_rating) . ')</span></p>';
                echo '<p><strong>DMARC:</strong> ' . esc_html($dmarc_result) . ' <span style="color: ' . ($dmarc_rating == 'Good' ? 'green' : 'red') . ';">(' . esc_html($dmarc_rating) . ')</span></p>';
                echo '<p><strong>DKIM:</strong> ' . esc_html($dkim_result) . ' <span style="color: ' . ($dkim_rating == 'Good' ? 'green' : 'red') . ';">(' . esc_html($dkim_rating) . ')</span></p>';
                echo '<p><strong>BIMI:</strong> ' . esc_html($bimi_result) . ' <span style="color: ' . ($bimi_rating == 'Good' ? 'green' : 'red') . ';">(' . esc_html($bimi_rating) . ')</span></p>';
            }
            ?>
        </div>
        <?php
    }

    function email_checker_check_spf($domain) {
        $records = dns_get_record('_spf.' . $domain, DNS_TXT);
        if ($records) {
            $result = implode(', ', array_map(function($record) { return $record['txt']; }, $records));
            $rating = strpos($result, 'v=spf1') !== false ? 'Good' : 'Bad';
            return [$result, $rating];
        }
        return ['No SPF record found.', 'Bad'];
    }

    function email_checker_check_dmarc($domain) {
        $records = dns_get_record('_dmarc.' . $domain, DNS_TXT);
        if ($records) {
            $result = implode(', ', array_map(function($record) { return $record['txt']; }, $records));
            $rating = strpos($result, 'v=DMARC1') !== false && (strpos($result, 'p=none') !== false || strpos($result, 'p=quarantine') !== false || strpos($result, 'p=reject') !== false) ? 'Good' : 'Bad';
            return [$result, $rating];
        }
        return ['No DMARC record found.', 'Bad'];
    }

    function email_checker_check_dkim($domain, $selector = 'default') {
        $records = dns_get_record($selector . '._domainkey.' . $domain, DNS_TXT);
        if ($records) {
            $result = implode(', ', array_map(function($record) { return $record['txt']; }, $records));
            $rating = strpos($result, 'v=DKIM1') !== false ? 'Good' : 'Bad';
            return [$result, $rating];
        }
        return ['No DKIM record found.', 'Bad'];
    }

    function email_checker_check_bimi($domain) {
        $records = dns_get_record('_bimi.' . $domain, DNS_TXT);
        if ($records) {
            $result = implode(', ', array_map(function($record) { return $record['txt']; }, $records));
            $rating = strpos($result, 'v=BIMI1') !== false ? 'Good' : 'Bad';
            return [$result, $rating];
        }
        return ['No BIMI record found.', 'Bad'];
    }

    function email_checker_shortcode() {
        ob_start();
        ?>
        <div class="email-checker">
            <h2>Email Checker</h2>
            <form method="post" action="">
                <?php wp_nonce_field('email_checker_nonce_action', 'email_checker_nonce'); ?>
                <label for="domain">Domain:</label>
                <input type="text" id="domain" name="domain" required />
                <button type="submit">Check</button>
            </form>

            <?php
            if (isset($_POST['domain']) && check_admin_referer('email_checker_nonce_action', 'email_checker_nonce')) {
                $domain = sanitize_text_field($_POST['domain']);

                list($spf_result, $spf_rating) = email_checker_check_spf($domain);
                list($dmarc_result, $dmarc_rating) = email_checker_check_dmarc($domain);
                list($dkim_result, $dkim_rating) = email_checker_check_dkim($domain, 'default'); // Assuming default selector
                list($bimi_result, $bimi_rating) = email_checker_check_bimi($domain);

                echo '<h3>Results for ' . esc_html($domain) . '</h3>';
                echo '<p><strong>SPF:</strong> ' . esc_html($spf_result) . ' <span style="color: ' . ($spf_rating == 'Good' ? 'green' : 'red') . ';">(' . esc_html($spf_rating) . ')</span></p>';
                echo '<p><strong>DMARC:</strong> ' . esc_html($dmarc_result) . ' <span style="color: ' . ($dmarc_rating == 'Good' ? 'green' : 'red') . ';">(' . esc_html($dmarc_rating) . ')</span></p>';
                echo '<p><strong>DKIM:</strong> ' . esc_html($dkim_result) . ' <span style="color: ' . ($dkim_rating == 'Good' ? 'green' : 'red') . ';">(' . esc_html($dkim_rating) . ')</span></p>';
                echo '<p><strong>BIMI:</strong> ' . esc_html($bimi_result) . ' <span style="color: ' . ($bimi_rating == 'Good' ? 'green' : 'red') . ';">(' . esc_html($bimi_rating) . ')</span></p>';
            }
            ?>
        </div>
        <?php
        return ob_get_clean();
    }
    add_shortcode('email_checker', 'email_checker_shortcode');
    ?>
