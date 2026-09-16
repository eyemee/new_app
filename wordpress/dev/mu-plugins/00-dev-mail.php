<?php
/**
 * Plugin Name: Dev Mail Catcher
 * Description: 開発環境でのみ、送信メールを Mailpit に向ける。本番へは持っていかない。
 *
 * 問い合わせフォームの通知・自動返信が実際に飛ぶかどうかを、
 * 外部に1通も出さずに確認するためのもの。
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action(
	'phpmailer_init',
	static function ( $phpmailer ) {
		if ( ! defined( 'SEIZO_DEV_MAIL_HOST' ) ) {
			return;
		}

		$phpmailer->isSMTP();
		$phpmailer->Host       = SEIZO_DEV_MAIL_HOST;
		$phpmailer->Port       = 1025;
		$phpmailer->SMTPAuth   = false;
		$phpmailer->SMTPAutoTLS = false;
	}
);
