<?php
    class Domain_Checker_Admin {
        public function __construct() {
            add_action('admin_menu', array($this, 'add_admin_menu'));
            add_action('admin_init', array($this, 'register_settings'));
        }

        public function add_admin_menu() {
            add_options_page(
                __('Domain Checker Settings', 'domain-checker'),
                __('Domain Checker', 'domain-checker'),
                'manage_options',
                'domain-checker-settings',
                array($this, 'settings_page')
            );
        }

        public function register_settings() {
            register_setting('domain_checker_options', 'domain_checker_settings');

            add_settings_section(
                'domain_checker_main',
                __('Main Settings', 'domain-checker'),
                array($this, 'settings_section_callback'),
                'domain-checker-settings'
            );

            add_settings_field(
                'dkim_selectors',
                __('DKIM Selectors', 'domain-checker'),
                array($this, 'dkim_selectors_callback'),
                'domain-checker-settings',
                'domain_checker_main'
            );
        }

        public function settings_section_callback() {
            echo '<p>' . esc_html__('Configure the Domain Security Checker settings below.', 'domain-checker') . '</p>';
        }

        public function dkim_selectors_callback() {
            $options = get_option('domain_checker_settings');
            $selectors = isset($options['dkim_selectors']) ? $options['dkim_selectors'] : 'default,google,selector1,selector2,dkim,mail';
            ?>
            <input type="text" 
                   name="domain_checker_settings[dkim_selectors]" 
                   value="<?php echo esc_attr($selectors); ?>" 
                   class="regular-text"
            />
            <p class="description">
                <?php esc_html_e('Comma-separated list of DKIM selectors to check', 'domain-checker'); ?>
            </p>
            <?php
        }

        public function settings_page() {
            if (!current_user_can('manage_options')) {
                return;
            }
            ?>
            <div class="wrap">
                <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
                <form action="options.php" method="post">
                    <?php
                    settings_fields('domain_checker_options');
                    do_settings_sections('domain-checker-settings');
                    submit_button();
                    ?>
                </form>
            </div>
            <?php
        }
    }
