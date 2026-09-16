<?php
/**
 * お知らせ（News）。
 *
 * 今フェーズで唯一クライアントが更新する領域。投稿タイプは標準の「投稿」ではなく
 * 専用の news を使う。標準投稿を残すと、管理画面に今回使わない導線が増えるため。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * 投稿タイプとカテゴリーの登録。
 */
function seizo_register_news() {
	register_post_type(
		'news',
		array(
			'labels'        => array(
				'name'               => 'お知らせ',
				'singular_name'      => 'お知らせ',
				'add_new'            => '新規追加',
				'add_new_item'       => 'お知らせを新規追加',
				'edit_item'          => 'お知らせを編集',
				'new_item'           => '新しいお知らせ',
				'view_item'          => 'お知らせを表示',
				'search_items'       => 'お知らせを検索',
				'not_found'          => 'お知らせはまだありません',
				'not_found_in_trash' => 'ゴミ箱にお知らせはありません',
				'all_items'          => 'お知らせ一覧',
				'menu_name'          => 'お知らせ',
			),
			'public'        => true,
			'has_archive'   => true,
			'rewrite'       => array( 'slug' => 'news', 'with_front' => false ),
			'menu_icon'     => 'dashicons-megaphone',
			'menu_position' => 5,
			'supports'      => array( 'title', 'editor', 'thumbnail', 'excerpt', 'revisions' ),
			'show_in_rest'  => true,
			'taxonomies'    => array( 'news_category' ),
		)
	);

	register_taxonomy(
		'news_category',
		'news',
		array(
			'labels'            => array(
				'name'          => 'お知らせカテゴリー',
				'singular_name' => 'カテゴリー',
				'add_new_item'  => 'カテゴリーを追加',
				'edit_item'     => 'カテゴリーを編集',
				'menu_name'     => 'カテゴリー',
			),
			'public'            => true,
			'hierarchical'      => true,
			'show_admin_column' => true,
			'show_in_rest'      => true,
			'rewrite'           => array( 'slug' => 'news/category', 'with_front' => false ),
		)
	);
}
add_action( 'init', 'seizo_register_news' );

/**
 * 初期カテゴリーを用意する。空の選択肢だけ渡してもクライアントは運用できないため、
 * 製造業のコーポレートサイトで実際に使う4種を既定として入れておく。
 */
function seizo_seed_news_categories() {
	$defaults = array(
		'お知らせ'   => 'info',
		'製品情報'   => 'product',
		'採用情報'   => 'recruit',
		'プレスリリース' => 'press',
	);

	foreach ( $defaults as $label => $slug ) {
		if ( ! term_exists( $slug, 'news_category' ) ) {
			wp_insert_term( $label, 'news_category', array( 'slug' => $slug ) );
		}
	}
}

/**
 * 一覧・カード表示用の日付。
 *
 * @param int|WP_Post|null $post 対象記事。
 * @return string
 */
function seizo_news_date( $post = null ) {
	return get_the_date( 'Y.m.d', $post );
}

/**
 * 記事に紐づくカテゴリーを1件返す。カードのラベル表示用。
 *
 * @param int|WP_Post|null $post 対象記事。
 * @return WP_Term|null
 */
function seizo_news_category( $post = null ) {
	$terms = get_the_terms( $post ?: get_the_ID(), 'news_category' );

	if ( is_wp_error( $terms ) || empty( $terms ) ) {
		return null;
	}

	return $terms[0];
}

/**
 * 抜粋。本文しかない記事でも一覧が崩れないように長さを揃える。
 *
 * @param int $length 文字数。
 * @return string
 */
function seizo_news_excerpt( $length = 70 ) {
	$text = has_excerpt() ? get_the_excerpt() : wp_strip_all_tags( get_the_content() );
	$text = trim( preg_replace( '/\s+/u', ' ', $text ) );

	if ( mb_strlen( $text ) > $length ) {
		$text = mb_substr( $text, 0, $length ) . '…';
	}

	return $text;
}

/**
 * 直近のお知らせを取得する。トップページ用。
 *
 * @param int $count 件数。
 * @return WP_Post[]
 */
function seizo_recent_news( $count = 4 ) {
	return get_posts(
		array(
			'post_type'        => 'news',
			'posts_per_page'   => $count,
			'post_status'      => 'publish',
			'suppress_filters' => false,
		)
	);
}
