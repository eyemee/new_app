<?php
/**
 * テスト用の WordPress スタブ。
 *
 * WordPress を起動せずに、テーマ内の純粋なロジック（入力検証・郵便番号の
 * 正規化など）を検証するための最小限の関数群。実装の挙動に合わせてあり、
 * 本物の WordPress を置き換えるものではない。
 */

define( 'ABSPATH', __DIR__ . '/' );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
define( 'MONTH_IN_SECONDS', 2592000 );

define( 'SEIZO_VERSION', 'test' );
define( 'SEIZO_DIR', dirname( __DIR__ ) . '/wp-content/themes/seizo' );
define( 'SEIZO_URI', 'http://localhost:8080/wp-content/themes/seizo' );
define( 'SEIZO_CONTACT_TO', 'test@example.co.jp' );

$GLOBALS['seizo_test_transients'] = array();
$GLOBALS['seizo_test_filters']    = array();
$GLOBALS['seizo_test_remote']     = null;
$GLOBALS['seizo_test_mail']       = array();

function add_action( $hook, $callback, $priority = 10, $args = 1 ) { return true; }
function add_filter( $hook, $callback, $priority = 10, $args = 1 ) { return true; }
function remove_action( $hook, $callback, $priority = 10 ) { return true; }

function apply_filters( $hook, $value ) {
	$args = func_get_args();

	if ( empty( $GLOBALS['seizo_test_filters'][ $hook ] ) ) {
		return $value;
	}

	foreach ( $GLOBALS['seizo_test_filters'][ $hook ] as $callback ) {
		$value = call_user_func_array( $callback, array_slice( $args, 1 ) );
		$args[1] = $value;
	}

	return $value;
}

function seizo_test_add_filter( $hook, $callback ) {
	$GLOBALS['seizo_test_filters'][ $hook ][] = $callback;
}

function seizo_test_reset() {
	$GLOBALS['seizo_test_transients'] = array();
	$GLOBALS['seizo_test_filters']    = array();
	$GLOBALS['seizo_test_remote']     = null;
	$GLOBALS['seizo_test_mail']       = array();
	$_POST                            = array();
	$_SERVER['REMOTE_ADDR']           = '203.0.113.10';
}

function get_transient( $key ) {
	return $GLOBALS['seizo_test_transients'][ $key ] ?? false;
}

function set_transient( $key, $value, $ttl = 0 ) {
	$GLOBALS['seizo_test_transients'][ $key ] = $value;
	return true;
}

function wp_unslash( $value ) {
	return is_string( $value ) ? stripslashes( $value ) : $value;
}

function sanitize_text_field( $value ) {
	$value = is_string( $value ) ? $value : '';
	$value = strip_tags( $value );
	$value = preg_replace( '/[\r\n\t]+/', ' ', $value );
	return trim( $value );
}

function sanitize_textarea_field( $value ) {
	$value = is_string( $value ) ? $value : '';
	return trim( strip_tags( $value ) );
}

function sanitize_email( $value ) {
	$value = is_string( $value ) ? $value : '';
	return trim( strip_tags( $value ) );
}

function sanitize_key( $value ) {
	return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $value ) );
}

function is_email( $value ) {
	return (bool) filter_var( $value, FILTER_VALIDATE_EMAIL );
}

function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function esc_url( $value )  { return (string) $value; }
function esc_url_raw( $value ) { return (string) $value; }
function esc_textarea( $value ) { return esc_html( $value ); }

function get_option( $key, $default = false ) { return $default; }
function get_bloginfo( $key ) { return 'テスト製作所'; }
function wp_specialchars_decode( $value, $flags = null ) { return $value; }
function wp_date( $format ) { return date( $format ); }
function home_url( $path = '/' ) { return 'http://localhost:8080' . $path; }
function get_permalink( $post = null ) { return 'http://localhost:8080/contact/'; }
function add_query_arg( $key, $value = '', $url = '' ) {
	if ( is_array( $key ) ) {
		return $url;
	}
	return $url . ( str_contains( (string) $url, '?' ) ? '&' : '?' ) . $key . '=' . $value;
}

function wp_mail( $to, $subject, $body, $headers = array() ) {
	$GLOBALS['seizo_test_mail'][] = compact( 'to', 'subject', 'body', 'headers' );
	return true;
}

function wp_remote_get( $url, $args = array() ) {
	return $GLOBALS['seizo_test_remote'] ?? new WP_Error( 'no_stub', 'not configured' );
}

function wp_remote_retrieve_body( $response ) { return $response['body'] ?? ''; }
function wp_remote_retrieve_response_code( $response ) { return $response['response']['code'] ?? 0; }

function is_wp_error( $thing ) { return $thing instanceof WP_Error; }

class WP_Error {
	public $code;
	public $message;

	public function __construct( $code = '', $message = '' ) {
		$this->code    = $code;
		$this->message = $message;
	}
}

// テーマ本体を読み込む。
require_once SEIZO_DIR . '/inc/contact.php';
require_once SEIZO_DIR . '/inc/zipcode.php';
