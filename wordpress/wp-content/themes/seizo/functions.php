<?php
/**
 * テーマのブートストラップ。
 *
 * 実装は inc/ 配下に機能単位で分割し、このファイルは読み込みのみを担当する。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SEIZO_VERSION', '1.0.0' );
define( 'SEIZO_DIR', get_template_directory() );
define( 'SEIZO_URI', get_template_directory_uri() );

/**
 * 問い合わせ通知の宛先。
 *
 * 本番はクライアントの受信アドレスに差し替える。wp-config.php に
 * SEIZO_CONTACT_TO を定義すればサーバー側で上書きできる。
 */
if ( ! defined( 'SEIZO_CONTACT_TO' ) ) {
	define( 'SEIZO_CONTACT_TO', get_option( 'admin_email' ) );
}

require_once SEIZO_DIR . '/inc/setup.php';
require_once SEIZO_DIR . '/inc/assets.php';
require_once SEIZO_DIR . '/inc/template-tags.php';
require_once SEIZO_DIR . '/inc/news.php';
require_once SEIZO_DIR . '/inc/zipcode.php';
require_once SEIZO_DIR . '/inc/contact.php';
require_once SEIZO_DIR . '/inc/admin.php';
require_once SEIZO_DIR . '/inc/provision.php';
