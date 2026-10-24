<?php
/*
 * Plugin Name: Demo Fixture Plugin
 */
add_action('wp_ajax_demo_save', 'demo_save');
add_action('wp_ajax_nopriv_demo_lookup', 'demo_lookup');

function demo_save() {
    wp_verify_nonce($_POST['nonce'], 'demo');
    update_option('demo_setting', sanitize_text_field($_POST['value']));
    wp_send_json_success();
}

function demo_safe_save() {
    check_ajax_referer('demo', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_die();
    }
    update_option('demo_setting', sanitize_text_field($_POST['value']));
}

function demo_lookup() {
    global $wpdb;
    return $wpdb->get_results("SELECT * FROM {$wpdb->prefix}demo WHERE slug = '" . $_POST['slug'] . "'");
}

if (is_admin()) {
    update_option('demo_flag', 1);
}

register_rest_route('demo/v1', '/reset', array(
    'methods' => 'POST',
    'callback' => 'demo_reset',
    'permission_callback' => '__return_true',
));
