<?php
/**
 * テンプレート描画テスト用のスタブ。
 *
 * bootstrap.php のスタブに、テンプレートが呼ぶ表示系の関数を足したもの。
 * WordPress を起動せずにテンプレートを実行し、実行時エラーが出ないこと・
 * HTML のタグが閉じていることを確認するために使う。
 */

require_once __DIR__ . '/bootstrap.php';

// 警告・注意も例外にする。未定義変数や引数不足を見逃さないため。
set_error_handler(
	static function ( $severity, $message, $file, $line ) {
		throw new ErrorException( $message, 0, $severity, $file, $line );
	}
);

class Seizo_Test_Post {
	public $ID;
	public $post_title;
	public $post_name;
	public $post_content;
	public $post_date;

	public function __construct( $id, $title, $name = '', $content = '' ) {
		$this->ID           = $id;
		$this->post_title   = $title;
		$this->post_name    = $name;
		$this->post_content = $content;
		$this->post_date    = '2025-09-01 10:00:00';
	}
}

class Seizo_Test_Term {
	public $term_id;
	public $name;
	public $slug;

	public function __construct( $id, $name, $slug ) {
		$this->term_id = $id;
		$this->name    = $name;
		$this->slug    = $slug;
	}
}

$GLOBALS['seizo_ctx'] = array(
	'posts'      => array(),
	'index'      => -1,
	'page'       => '',
	'front'      => false,
	'archive'    => false,
	'tax'        => false,
	'single'     => false,
	'search'     => false,
	'queried'    => null,
);

function seizo_ctx( $key ) {
	return $GLOBALS['seizo_ctx'][ $key ];
}

function seizo_set_ctx( array $ctx ) {
	$GLOBALS['seizo_ctx'] = array_merge(
		array(
			'posts' => array(), 'index' => -1, 'page' => '', 'front' => false,
			'archive' => false, 'tax' => false, 'single' => false,
			'search' => false, 'queried' => null,
		),
		$ctx
	);
}

function seizo_sample_posts( $count = 3 ) {
	$posts = array();
	for ( $i = 1; $i <= $count; $i++ ) {
		$posts[] = new Seizo_Test_Post(
			$i,
			'新工場の稼働を開始しました ' . $i,
			'news-' . $i,
			"<p>本文の段落です。</p>\n<h2>見出し</h2>\n<p>続きの段落。</p>"
		);
	}
	return $posts;
}

/* --- テンプレート読み込み ------------------------------------ */

function get_header( $name = null ) { include SEIZO_DIR . '/header.php'; }
function get_footer( $name = null ) { include SEIZO_DIR . '/footer.php'; }
function get_template_part( $slug, $name = null ) { include SEIZO_DIR . '/' . $slug . '.php'; }
function get_template_directory() { return SEIZO_DIR; }
function get_template_directory_uri() { return SEIZO_URI; }

/* --- ループ -------------------------------------------------- */

function have_posts() {
	$ctx = $GLOBALS['seizo_ctx'];
	return ( $ctx['index'] + 1 ) < count( $ctx['posts'] );
}

function the_post() {
	$GLOBALS['seizo_ctx']['index']++;
	$GLOBALS['post'] = $GLOBALS['seizo_ctx']['posts'][ $GLOBALS['seizo_ctx']['index'] ];
}

function setup_postdata( $post ) { $GLOBALS['post'] = $post; return true; }
function wp_reset_postdata() { return true; }

function seizo_current_post() {
	return $GLOBALS['post'] ?? new Seizo_Test_Post( 0, '記事' );
}

/* --- 条件分岐 ------------------------------------------------ */

function is_front_page() { return (bool) seizo_ctx( 'front' ); }
function is_page( $slug = '' ) {
	$page = seizo_ctx( 'page' );
	return '' === $slug ? '' !== $page : $page === $slug;
}
function is_singular( $type = '' ) {
	if ( 'page' === $type ) { return '' !== seizo_ctx( 'page' ); }
	if ( 'news' === $type ) { return (bool) seizo_ctx( 'single' ); }
	return '' !== seizo_ctx( 'page' ) || seizo_ctx( 'single' );
}
function is_post_type_archive( $type = '' ) { return (bool) seizo_ctx( 'archive' ); }
function is_tax( $tax = '' ) { return (bool) seizo_ctx( 'tax' ); }
function is_search() { return (bool) seizo_ctx( 'search' ); }
function is_admin() { return false; }
function get_queried_object() { return seizo_ctx( 'queried' ); }
function get_post( $post = null ) { return $post ?: seizo_current_post(); }

/* --- 記事データ ---------------------------------------------- */

function get_the_ID() { return seizo_current_post()->ID; }
function get_the_title( $post = null ) {
	if ( is_object( $post ) ) { return $post->post_title; }
	if ( is_int( $post ) ) { return '記事 ' . $post; }
	return seizo_current_post()->post_title;
}
function the_title() { echo esc_html( get_the_title() ); }
function get_permalink_for( $post ) { return 'http://localhost:8080/news/' . $post->post_name . '/'; }
function the_permalink() { echo esc_url( get_permalink_for( seizo_current_post() ) ); }
function get_the_date( $format = '', $post = null ) {
	return 'c' === $format ? '2025-09-01T10:00:00+09:00' : date( $format ?: 'Y.m.d', strtotime( '2025-09-01' ) );
}
function get_the_content() { return seizo_current_post()->post_content; }
function the_content() { echo get_the_content(); }
function get_the_excerpt() { return '抜粋のテキストです。'; }
function has_excerpt() { return false; }
function wp_strip_all_tags( $text ) { return strip_tags( (string) $text ); }
function has_post_thumbnail() { return true; }
function the_post_thumbnail( $size = '', $attr = array() ) {
	echo '<img src="' . esc_url( SEIZO_URI . '/assets/img/news.jpg' ) . '" alt="" width="640" height="400">';
}
function get_the_terms( $post, $taxonomy ) {
	return array( new Seizo_Test_Term( 1, 'お知らせ', 'info' ) );
}
function get_terms( $args = array() ) {
	return array(
		new Seizo_Test_Term( 1, 'お知らせ', 'info' ),
		new Seizo_Test_Term( 2, '製品情報', 'product' ),
	);
}
function get_term_link( $term ) { return 'http://localhost:8080/news/category/' . $term->slug . '/'; }
function get_post_type_archive_link( $type ) { return 'http://localhost:8080/news/'; }
function get_previous_post() { return new Seizo_Test_Post( 98, '前の記事', 'prev' ); }
function get_next_post() { return new Seizo_Test_Post( 99, '次の記事', 'next' ); }
function get_posts( $args = array() ) { return seizo_sample_posts( $args['posts_per_page'] ?? 3 ); }
function get_page_by_path( $path ) { return null; }

/* --- 出力まわり ---------------------------------------------- */

function language_attributes() { echo 'lang="ja"'; }
function bloginfo( $key ) { echo 'テスト製作所'; }
function body_class( $class = '' ) {
	$classes = apply_filters( 'body_class', array( 'seizo' ) );
	echo 'class="' . esc_attr( implode( ' ', $classes ) ) . '"';
}
function wp_head() { echo "<!-- wp_head -->\n"; }
function wp_footer() { echo "<!-- wp_footer -->\n"; }
function wp_body_open() {}
function has_custom_logo() { return false; }
function the_custom_logo() {}
function wp_nav_menu( $args = array() ) {
	if ( is_callable( $args['fallback_cb'] ?? null ) ) {
		call_user_func( $args['fallback_cb'] );
	}
}
function paginate_links( $args = array() ) {
	return array(
		'<a class="page-numbers" href="http://localhost:8080/news/page/1/">1</a>',
		'<span class="page-numbers current">2</span>',
	);
}
function wp_kses_post( $value ) { return $value; }
function wp_nonce_field( $action, $name ) {
	echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="testnonce">';
}
function checked( $a, $b = true, $echo = true ) { if ( $a == $b ) { echo ' checked'; } }
function selected( $a, $b = true, $echo = true ) { if ( $a == $b ) { echo ' selected'; } }

// 会社情報とテンプレートタグを読み込む。
require_once SEIZO_DIR . '/inc/setup.php';
require_once SEIZO_DIR . '/inc/template-tags.php';
require_once SEIZO_DIR . '/inc/news.php';
