<?php
    /*
    Plugin Name: Domain Security Checker
    Plugin URI: https://immutec.com
    Description: Check domain security settings including SPF, DMARC, DKIM, BIMI, and more
    Version: 1.0
    Author: P.Verleye / Immutec
    Author URI: https://immutec.com
    */

    // Prevent direct access to this file
    if (!defined('ABSPATH')) {
        exit;
    }

    // Define plugin constants
    define('DOMAIN_CHECKER_VERSION', '1.0');
    define('DOMAIN_CHECKER_PLUGIN_DIR', plugin_dir_path(__FILE__));
    define('DOMAIN_CHECKER_PLUGIN_URL', plugin_dir_url(__FILE__));

    // Include required files
    require_once DOMAIN_CHECKER_PLUGIN_DIR . 'includes/class-domain-checker.php';
    require_once DOMAIN_CHECKER_PLUGIN_DIR . 'includes/class-domain-checker-widget.php';

    class DomainCheckerPlugin {
        private static $instance = null;

        public static function get_instance() {
            if (null === self::$instance) {
                self::$instance = new self();
            }
            return self::$instance;
        }

        private function __construct() {
            add_action('init', array($this, 'init'));
            add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
            add_shortcode('domain_checker', array($this, 'shortcode_handler'));
            add_action('widgets_init', array($this, 'register_widget'));
            add_action('wp_ajax_check_domain', array($this, 'ajax_check_domain'));
            add_action('wp_ajax_nopriv_check_domain', array($this, 'ajax_check_domain'));
        }

        public function init() {
            load_plugin_textdomain('domain-checker', false, dirname(plugin_basename(__FILE__)) . '/languages');
        }

        public function enqueue_scripts() {
            wp_enqueue_style(
                'domain-checker-styles',
                DOMAIN_CHECKER_PLUGIN_URL . 'assets/css/styles.css',
                array(),
                DOMAIN_CHECKER_VERSION
            );

            wp_enqueue_script(
                'domain-checker-script',
                DOMAIN_CHECKER_PLUGIN_URL . 'assets/js/script.js',
                array('jquery'),
                DOMAIN_CHECKER_VERSION,
                true
            );

            wp_localize_script('domain-checker-script', 'domainCheckerAjax', array(
                'ajaxurl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('domain_checker_nonce')
            ));
        }

        public function register_widget() {
            register_widget('Domain_Checker_Widget');
        }

        public function shortcode_handler($atts) {
            ob_start();
            include DOMAIN_CHECKER_PLUGIN_DIR . 'templates/checker-form.php';
            return ob_get_clean();
        }

        public function ajax_check_domain() {
            check_ajax_referer('domain_checker_nonce', 'nonce');

            $domain = sanitize_text_field($_POST['domain'] ?? '');
            if (empty($domain)) {
                wp_send_json_error('Please enter a domain');
            }

            try {
                $checker = new DomainChecker();
                $results = $checker->checkAll($domain);
                wp_send_json_success($results);
            } catch (Exception $e) {
                wp_send_json_error($e->getMessage());
            }
        }
    }

    // Initialize the plugin
    function domain_checker_init() {
        return DomainCheckerPlugin::get_instance();
    }
    add_action('plugins_loaded', 'domain_checker_init');

    // Activation hook
    register_activation_hook(__FILE__, 'domain_checker_activate');
    function domain_checker_activate() {
        // Activation tasks if needed
    }

    // Deactivation hook
    register_deactivation_hook(__FILE__, 'domain_checker_deactivate');
    function domain_checker_deactivate() {
        // Cleanup tasks if needed
    }
    ?>
