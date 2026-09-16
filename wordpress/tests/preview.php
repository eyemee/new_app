<?php
/**
 * 静的プレビューの書き出し。
 *
 *   php tests/preview.php <出力先ディレクトリ>
 *
 * 各テンプレートを描画し、CSS を埋め込んだ単体で開ける HTML を書き出す。
 * Docker を立てずにデザインの当たりを確認するためのもので、納品物ではない。
 * 画像は未入稿のため、プレースホルダに差し替えて出力する。
 */

require_once __DIR__ . '/render-stubs.php';

$out = $argv[1] ?? sys_get_temp_dir() . '/seizo-preview';

if ( ! is_dir( $out ) ) {
	mkdir( $out, 0777, true );
}

/** CSS を1つにまとめる（読み込み順は inc/assets.php と同じ）。 */
function preview_css() {
	$css = '';

	foreach ( array( 'tokens', 'base', 'components', 'pages' ) as $name ) {
		$css .= "\n/* ===== " . $name . ".css ===== */\n";
		$css .= file_get_contents( SEIZO_DIR . '/assets/css/' . $name . '.css' );
	}

	return $css;
}

/** 未入稿の画像をプレースホルダに差し替える。 */
function preview_placeholders( $html ) {
	$svg = rawurlencode(
		'<svg xmlns="http://www.w3.org/2000/svg" width="800" height="500">' .
		'<rect width="800" height="500" fill="#e4e9ee"/>' .
		'<path d="M0 0l800 500M800 0L0 500" stroke="#cdd5dd" stroke-width="2"/>' .
		'<text x="400" y="258" text-anchor="middle" font-family="sans-serif" ' .
		'font-size="26" fill="#8894a0">AI 入稿画像</text></svg>'
	);

	return preg_replace(
		'#src="[^"]*/assets/img/[^"]*"#',
		'src="data:image/svg+xml;charset=utf-8,' . $svg . '"',
		$html
	);
}

/** 1ページ書き出す。 */
function preview_write( $out, $file, $template, array $ctx, $before = null ) {
	seizo_set_ctx( $ctx );

	if ( $before ) {
		$before();
	}

	ob_start();
	include SEIZO_DIR . '/' . $template;
	$html = ob_get_clean();

	$html = preview_placeholders( $html );

	// wp_head() の位置に CSS を差し込む。
	$html = str_replace(
		'<!-- wp_head -->',
		"<style>\n" . preview_css() . "\n</style>",
		$html
	);

	// プレビュー間を行き来できるバーを足す。
	$bar = '<div style="position:fixed;bottom:0;left:0;right:0;z-index:9999;'
		. 'background:#0b1f36;color:#fff;font:12px/1.6 sans-serif;padding:8px 12px;text-align:center">'
		. '静的プレビュー（画像は未入稿・プレースホルダ）&nbsp;&nbsp;'
		. '<a style="color:#9ec5f5" href="index.html">トップ</a> / '
		. '<a style="color:#9ec5f5" href="company.html">会社概要</a> / '
		. '<a style="color:#9ec5f5" href="business.html">事業・製品</a> / '
		. '<a style="color:#9ec5f5" href="quality.html">品質・技術</a> / '
		. '<a style="color:#9ec5f5" href="recruit.html">採用情報</a> / '
		. '<a style="color:#9ec5f5" href="news.html">お知らせ</a> / '
		. '<a style="color:#9ec5f5" href="news-detail.html">お知らせ詳細</a> / '
		. '<a style="color:#9ec5f5" href="contact.html">お問い合わせ</a> / '
		. '<a style="color:#9ec5f5" href="contact-confirm.html">確認画面</a>'
		. '</div></body>';

	$html = str_replace( '</body>', $bar, $html );

	file_put_contents( $out . '/' . $file, $html );
	printf( "  %-24s %7d bytes\n", $file, strlen( $html ) );
}

echo "\n静的プレビューを書き出します: " . $out . "\n\n";

preview_write( $out, 'index.html', 'front-page.php', array( 'front' => true, 'posts' => seizo_sample_posts( 4 ) ) );
preview_write( $out, 'company.html', 'page-company.php', array( 'page' => 'company', 'posts' => array( new Seizo_Test_Post( 10, '会社概要', 'company' ) ) ) );
preview_write( $out, 'business.html', 'page-business.php', array( 'page' => 'business', 'posts' => array( new Seizo_Test_Post( 11, '事業・製品', 'business' ) ) ) );
preview_write( $out, 'quality.html', 'page-quality.php', array( 'page' => 'quality', 'posts' => array( new Seizo_Test_Post( 12, '品質・技術', 'quality' ) ) ) );
preview_write( $out, 'recruit.html', 'page-recruit.php', array( 'page' => 'recruit', 'posts' => array( new Seizo_Test_Post( 13, '採用情報', 'recruit' ) ) ) );
preview_write( $out, 'news.html', 'archive-news.php', array( 'archive' => true, 'posts' => seizo_sample_posts( 6 ) ) );
preview_write( $out, 'news-detail.html', 'single-news.php', array( 'single' => true, 'posts' => seizo_sample_posts( 1 ) ) );

preview_write(
	$out, 'contact.html', 'page-contact.php',
	array( 'page' => 'contact', 'posts' => array( new Seizo_Test_Post( 15, 'お問い合わせ', 'contact' ) ) ),
	static function () {
		$state = &seizo_contact_state_ref();
		$state = array( 'step' => 'input', 'values' => array(), 'errors' => array() );
	}
);

preview_write(
	$out, 'contact-confirm.html', 'page-contact.php',
	array( 'page' => 'contact', 'posts' => array( new Seizo_Test_Post( 15, 'お問い合わせ', 'contact' ) ) ),
	static function () {
		$state = &seizo_contact_state_ref();
		$state = array(
			'step'   => 'confirm',
			'values' => array(
				'company'    => '株式会社テスト工業',
				'department' => '生産技術部',
				'name'       => '山田 太郎',
				'kana'       => 'ヤマダ タロウ',
				'email'      => 'yamada@example.co.jp',
				'tel'        => '052-123-4567',
				'zip'        => '460-0008',
				'prefecture' => '愛知県',
				'city'       => '名古屋市中区栄',
				'address'    => '1-1-1 テストビル 5F',
				'subject'    => 'お見積り・ご注文について',
				'message'    => "アルミ部品の加工をお願いしたく、ご連絡しました。\n図面は別途お送りします。",
				'privacy'    => '1',
			),
			'errors' => array(),
		);
	}
);

echo "\n完了\n\n";
