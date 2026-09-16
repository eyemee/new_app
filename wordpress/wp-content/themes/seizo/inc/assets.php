<?php
/**
 * CSS / JS の読み込み。
 *
 * ビルド工程を持たない構成にしている。理由は2つ:
 *  - 入稿 AI との突き合わせ時、ブラウザで見ている CSS とリポジトリの CSS が
 *    1対1で対応していないとピクセル調整の往復が増えるため。
 *  - 納品先がクライアントの既存サーバーで、Node を前提にできないため。
 * バージョンはファイル更新時刻から採るので、差し替え時のキャッシュ残りが起きない。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * ファイル更新時刻をアセットのバージョンとして返す。
 *
 * @param string $relative テーマルートからの相対パス。
 * @return string
 */
function seizo_asset_version( $relative ) {
	$path = SEIZO_DIR . '/' . ltrim( $relative, '/' );

	if ( file_exists( $path ) ) {
		return (string) filemtime( $path );
	}

	return SEIZO_VERSION;
}

/**
 * フロント側のアセットを登録する。
 */
function seizo_enqueue_assets() {
	// 読み込み順に意味がある。tokens -> base -> components -> pages。
	$styles = array( 'tokens', 'base', 'components', 'pages' );

	$previous = '';
	foreach ( $styles as $handle ) {
		$relative = 'assets/css/' . $handle . '.css';
		wp_enqueue_style(
			'seizo-' . $handle,
			SEIZO_URI . '/' . $relative,
			$previous ? array( $previous ) : array(),
			seizo_asset_version( $relative )
		);
		$previous = 'seizo-' . $handle;
	}

	wp_enqueue_script(
		'seizo-site',
		SEIZO_URI . '/assets/js/site.js',
		array(),
		seizo_asset_version( 'assets/js/site.js' ),
		true
	);

	// 郵便番号 → 住所の自動入力はお問い合わせページだけで使う。
	if ( is_page( 'contact' ) ) {
		wp_enqueue_script(
			'seizo-contact',
			SEIZO_URI . '/assets/js/contact.js',
			array(),
			seizo_asset_version( 'assets/js/contact.js' ),
			true
		);

		wp_localize_script(
			'seizo-contact',
			'seizoContact',
			array(
				'zipEndpoint' => esc_url_raw( rest_url( 'seizo/v1/zipcode' ) ),
				'nonce'       => wp_create_nonce( 'wp_rest' ),
			)
		);
	}
}
add_action( 'wp_enqueue_scripts', 'seizo_enqueue_assets' );

/**
 * 管理画面（お知らせ編集）に最低限のスタイルを当てる。
 * クライアントが本文を編集したときの見た目を、フロントと大きくずらさないため。
 */
function seizo_editor_styles() {
	add_theme_support( 'editor-styles' );
	add_editor_style( 'assets/css/editor.css' );
}
add_action( 'after_setup_theme', 'seizo_editor_styles' );
