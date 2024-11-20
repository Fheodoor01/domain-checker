<?php
    // If uninstall not called from WordPress, exit
    if (!defined('WP_UNINSTALL_PLUGIN')) {
        exit;
    }

    // Delete plugin options
    delete_option('domain_checker_settings');

    // Delete any other options and custom tables if created
    ?>
