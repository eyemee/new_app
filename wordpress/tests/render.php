<?php
/**
 * テンプレート描画テスト。
 *
 *   php tests/render.php
 *
 * 各テンプレートを実際に実行し、次を確認する。
 *   - 実行時エラー・警告・未定義変数が出ないこと（php -l では検出できない）
 *   - HTML のタグが正しく閉じていること
 *   - そのページに出ているべき要素が出ていること
 */

require_once __DIR__ . '/render-stubs.php';

$passed = 0;
$failed = 0;

function report( $name, $ok, $detail = '' ) {
	global $passed, $failed;

	if ( $ok ) {
		$passed++;
		printf( "  ok   %s\n", $name );
		return;
	}

	$failed++;
	printf( "  FAIL %s%s\n", $name, $detail ? "\n       " . $detail : '' );
}

/**
 * HTML のタグの対応を確認する。
 *
 * @param string $html 対象。
 * @return string 問題があれば説明、なければ空文字。
 */
function check_tags( $html ) {
	$void = array(
		'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
		'link', 'meta', 'param', 'source', 'track', 'wbr', '!doctype',
	);

	// コメントとスクリプトの中身は対象外。
	$html  = preg_replace( '/<!--.*?-->/s', '', $html );
	$stack = array();

	preg_match_all( '/<(\/?)([a-zA-Z0-9!]+)([^>]*?)(\/?)>/s', $html, $matches, PREG_SET_ORDER );

	foreach ( $matches as $m ) {
		$closing = '/' === $m[1];
		$tag     = strtolower( $m[2] );
		$self    = '/' === $m[4];

		if ( in_array( $tag, $void, true ) || $self ) {
			continue;
		}

		if ( ! $closing ) {
			$stack[] = $tag;
			continue;
		}

		$open = array_pop( $stack );

		if ( $open !== $tag ) {
			return sprintf( '</%s> で閉じようとしたが、開いているのは <%s>', $tag, $open ?? 'なし' );
		}
	}

	if ( $stack ) {
		return '閉じられていないタグ: <' . implode( '>, <', $stack ) . '>';
	}

	return '';
}

/**
 * テンプレートを1つ描画して検証する。
 *
 * @param string        $seizo__label    表示名。
 * @param string        $seizo__template テンプレートファイル名。
 * @param array         $seizo__ctx      描画コンテキスト。
 * @param string[]      $seizo__expect   出力に含まれているべき文字列。
 * @param callable|null $seizo__before   描画前の追加処理。
 */
function render_case( $seizo__label, $seizo__template, array $seizo__ctx, array $seizo__expect = array(), $seizo__before = null ) {
	// ローカル変数に seizo__ を付けているのは、include したテンプレート側の
	// foreach ( ... as $label => $value ) がこの関数のスコープを共有し、
	// 素の名前だと上書きされてしまうため（テスト結果の表示が壊れる）。
	seizo_set_ctx( $seizo__ctx );

	if ( $seizo__before ) {
		$seizo__before();
	}

	ob_start();
	$seizo__error = '';

	try {
		include SEIZO_DIR . '/' . $seizo__template;
	} catch ( Throwable $e ) {
		$seizo__error = get_class( $e ) . ': ' . $e->getMessage() .
			' (' . basename( $e->getFile() ) . ':' . $e->getLine() . ')';
	}

	$seizo__html = ob_get_clean();

	if ( $seizo__error ) {
		report( $seizo__label . ' — 実行時エラーなし', false, $seizo__error );
		return;
	}

	report( $seizo__label . ' — 実行時エラーなし', true );

	$seizo__tag_problem = check_tags( $seizo__html );
	report( $seizo__label . ' — タグの対応', '' === $seizo__tag_problem, $seizo__tag_problem );

	foreach ( $seizo__expect as $seizo__needle ) {
		report(
			sprintf( '%s — "%s" が出力される', $seizo__label, mb_substr( $seizo__needle, 0, 28 ) ),
			str_contains( $seizo__html, $seizo__needle )
		);
	}
}

echo "\nテンプレートの描画\n";

render_case(
	'トップ',
	'front-page.php',
	array( 'front' => true, 'posts' => seizo_sample_posts( 4 ) ),
	array( '<!DOCTYPE html>', 'class="p-hero"', 'OUR BUSINESS', 'c-news-card', '</html>' )
);

render_case(
	'会社概要',
	'page-company.php',
	array( 'page' => 'company', 'posts' => array( new Seizo_Test_Post( 10, '会社概要', 'company' ) ) ),
	array( 'c-page-hero__title', 'COMPANY', 'c-history', '1958年' )
);

render_case(
	'事業・製品',
	'page-business.php',
	array( 'page' => 'business', 'posts' => array( new Seizo_Test_Post( 11, '事業・製品', 'business' ) ) ),
	array( 'BUSINESS', 'p-business-products', 'target="_blank"', 'rel="noopener"' )
);

render_case(
	'品質・技術',
	'page-quality.php',
	array( 'page' => 'quality', 'posts' => array( new Seizo_Test_Post( 12, '品質・技術', 'quality' ) ) ),
	array( 'QUALITY', 'c-flow', 'トレーサビリティ' )
);

render_case(
	'採用情報',
	'page-recruit.php',
	array( 'page' => 'recruit', 'posts' => array( new Seizo_Test_Post( 13, '採用情報', 'recruit' ) ) ),
	array( 'RECRUIT', 'p-recruit-position' )
);

render_case(
	'お知らせ一覧',
	'archive-news.php',
	array( 'archive' => true, 'posts' => seizo_sample_posts( 5 ) ),
	array( 'c-filter', 'c-news-card', 'c-pagination' )
);

render_case(
	'お知らせ詳細',
	'single-news.php',
	array( 'single' => true, 'posts' => seizo_sample_posts( 1 ) ),
	array( 'p-news-detail__title', 'c-post-nav', 'c-breadcrumb' )
);

render_case(
	'固定ページ（汎用）',
	'page.php',
	array( 'page' => 'privacy', 'posts' => array( new Seizo_Test_Post( 14, '個人情報保護方針', 'privacy', '<p>方針の本文。</p>' ) ) ),
	array( 'p-page__body', '方針の本文' )
);

render_case( '404', '404.php', array(), array( 'p-404', 'ページが見つかりません' ) );

render_case(
	'フォールバック（index）',
	'index.php',
	array( 'archive' => true, 'posts' => seizo_sample_posts( 2 ) ),
	array( 'p-news__list' )
);

echo "\nお問い合わせフォームの3画面\n";

render_case(
	'入力画面',
	'page-contact.php',
	array( 'page' => 'contact', 'posts' => array( new Seizo_Test_Post( 15, 'お問い合わせ', 'contact' ) ) ),
	array( 'name="seizo_action" value="confirm"', 'id="field-zip"', 'c-form__hp', 'name="seizo_contact_nonce"' ),
	static function () {
		$state = &seizo_contact_state_ref();
		$state = array( 'step' => 'input', 'values' => array(), 'errors' => array() );
	}
);

render_case(
	'入力エラー表示',
	'page-contact.php',
	array( 'page' => 'contact', 'posts' => array( new Seizo_Test_Post( 15, 'お問い合わせ', 'contact' ) ) ),
	array( 'is-error', 'role="alert"', '会社名を入力してください。' ),
	static function () {
		$state = &seizo_contact_state_ref();
		$state = array(
			'step'   => 'input',
			'values' => array( 'name' => '山田 太郎' ),
			'errors' => array( 'company' => '会社名を入力してください。' ),
		);
	}
);

render_case(
	'確認画面',
	'page-contact.php',
	array( 'page' => 'contact', 'posts' => array( new Seizo_Test_Post( 15, 'お問い合わせ', 'contact' ) ) ),
	array( 'name="seizo_action" value="send"', 'name="seizo_action" value="back"', '株式会社テスト' ),
	static function () {
		$state = &seizo_contact_state_ref();
		$state = array(
			'step'   => 'confirm',
			'values' => array(
				'company' => '株式会社テスト',
				'name'    => '山田 太郎',
				'kana'    => 'ヤマダ タロウ',
				'email'   => 'yamada@example.co.jp',
				'tel'     => '052-123-4567',
				'subject' => '製品について',
				'message' => "1行目\n2行目",
				'privacy' => '1',
			),
			'errors' => array(),
		);
	}
);

render_case(
	'完了画面',
	'page-contact.php',
	array( 'page' => 'contact', 'posts' => array( new Seizo_Test_Post( 15, 'お問い合わせ', 'contact' ) ) ),
	array( 'お問い合わせを受け付けました', 'p-contact__complete' ),
	static function () {
		$state = &seizo_contact_state_ref();
		$state = array( 'step' => 'complete', 'values' => array(), 'errors' => array() );
	}
);

echo "\n出力のエスケープ\n";

// 確認画面に危険な文字列を流し込み、そのまま出力されないことを確認する。
seizo_set_ctx( array( 'page' => 'contact', 'posts' => array( new Seizo_Test_Post( 15, 'お問い合わせ', 'contact' ) ) ) );
$state = &seizo_contact_state_ref();
$state = array(
	'step'   => 'confirm',
	'values' => array(
		'company' => '<script>alert(1)</script>',
		'name'    => '"><img src=x onerror=alert(1)>',
		'message' => '<b>太字</b>',
		'privacy' => '1',
	),
	'errors' => array(),
);

ob_start();
include SEIZO_DIR . '/page-contact.php';
$html = ob_get_clean();

report( 'script タグがそのまま出ない', ! str_contains( $html, '<script>alert(1)</script>' ) );
report( 'エスケープされて出力される', str_contains( $html, '&lt;script&gt;alert(1)&lt;/script&gt;' ) );
report( '属性からの脱出を許さない', ! str_contains( $html, '<img src=x onerror=alert(1)>' ) );
report( '本文の HTML もエスケープされる', str_contains( $html, '&lt;b&gt;太字&lt;/b&gt;' ) );

printf( "\n%d passed, %d failed\n\n", $passed, $failed );

exit( $failed > 0 ? 1 : 0 );
