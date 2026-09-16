<?php
/**
 * テーマの基本設定。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * テーマサポートとメニューの登録。
 */
function seizo_setup() {
	load_theme_textdomain( 'seizo', SEIZO_DIR . '/languages' );

	add_theme_support( 'title-tag' );
	add_theme_support( 'post-thumbnails' );
	add_theme_support( 'automatic-feed-links' );
	add_theme_support( 'responsive-embeds' );
	add_theme_support(
		'html5',
		array( 'search-form', 'gallery', 'caption', 'style', 'script', 'navigation-widgets' )
	);

	// お知らせのサムネイル。入稿デザインの実寸に合わせて調整する。
	add_image_size( 'seizo_news_card', 640, 400, true );
	add_image_size( 'seizo_news_hero', 1280, 720, true );

	register_nav_menus(
		array(
			'primary' => 'グローバルナビゲーション',
			'footer'  => 'フッターナビゲーション',
		)
	);
}
add_action( 'after_setup_theme', 'seizo_setup' );

/**
 * お知らせアーカイブの表示件数。
 *
 * @param WP_Query $query メインクエリ。
 */
function seizo_archive_query( $query ) {
	if ( is_admin() || ! $query->is_main_query() ) {
		return;
	}

	if ( $query->is_post_type_archive( 'news' ) || $query->is_tax( 'news_category' ) ) {
		$query->set( 'posts_per_page', 10 );
	}
}
add_action( 'pre_get_posts', 'seizo_archive_query' );

/**
 * 不要な出力の抑制。表示速度と、納品後の余計な差分を減らすため。
 */
function seizo_cleanup_head() {
	remove_action( 'wp_head', 'wp_generator' );
	remove_action( 'wp_head', 'wlwmanifest_link' );
	remove_action( 'wp_head', 'rsd_link' );
	remove_action( 'wp_head', 'wp_shortlink_wp_head' );
	remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
	remove_action( 'wp_print_styles', 'print_emoji_styles' );
}
add_action( 'init', 'seizo_cleanup_head' );

/**
 * ブロックエディタ用のインラインスタイルを front 側で読み込まない。
 * 今フェーズで編集対象になるのはお知らせ本文のみ、かつ素の HTML で組むため。
 */
function seizo_dequeue_block_styles() {
	wp_dequeue_style( 'wp-block-library' );
	wp_dequeue_style( 'wp-block-library-theme' );
	wp_dequeue_style( 'global-styles' );
	wp_dequeue_style( 'classic-theme-styles' );
}
add_action( 'wp_enqueue_scripts', 'seizo_dequeue_block_styles', 100 );

/**
 * コメント機能はこのサイトでは使わない。
 */
function seizo_disable_comments() {
	foreach ( get_post_types() as $post_type ) {
		if ( post_type_supports( $post_type, 'comments' ) ) {
			remove_post_type_support( $post_type, 'comments' );
			remove_post_type_support( $post_type, 'trackbacks' );
		}
	}
}
add_action( 'init', 'seizo_disable_comments', 20 );

add_filter( 'comments_open', '__return_false', 20 );
add_filter( 'pings_open', '__return_false', 20 );

/**
 * body に「どのページか」を判別できるクラスを足す。
 * ページ固有の詰めを CSS 側だけで完結させるため。
 *
 * @param string[] $classes body クラス。
 * @return string[]
 */
function seizo_body_class( $classes ) {
	if ( is_front_page() ) {
		$classes[] = 'p-home';
	} elseif ( is_singular( 'page' ) ) {
		$page = get_post();
		if ( $page instanceof WP_Post ) {
			$classes[] = 'p-' . $page->post_name;
		}
	} elseif ( is_singular( 'news' ) ) {
		$classes[] = 'p-news-detail';
	} elseif ( is_post_type_archive( 'news' ) || is_tax( 'news_category' ) ) {
		$classes[] = 'p-news';
	}

	return $classes;
}
add_filter( 'body_class', 'seizo_body_class' );

/**
 * 会社情報。フッター・会社概要・構造化データから参照する。
 *
 * ★要差し替え: 正式名称・住所・電話番号はクライアント確認後の値に置き換える。
 * 1か所にまとめてあるので、確定値が来たらこの配列だけ直せば全ページに反映される。
 *
 * @return array<string,string>
 */
function seizo_company() {
	return array(
		'name'      => '株式会社◯◯製作所',
		'name_en'   => 'MARUMARU SEISAKUSHO CO., LTD.',
		'founded'   => '1958',
		'zip'       => '〒460-0008',
		'address'   => '愛知県名古屋市中区栄◯丁目◯番◯号',
		'tel'       => '052-000-0000',
		'fax'       => '052-000-0001',
		'hours'     => '平日 9:00〜17:30（土日祝・年末年始を除く）',
		'legacy_url' => 'https://example.co.jp/products/',
	);
}
