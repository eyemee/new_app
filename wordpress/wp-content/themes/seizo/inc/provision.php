<?php
/**
 * テーマ有効化時の初期構築。
 *
 * このテーマは page-{slug}.php でページを出し分けるので、対応するスラッグの
 * 固定ページが存在しないと 404 になる。手作業での作成はスラッグの打ち間違いが
 * 起きるため、有効化時に自動で用意する。既存ページがある場合は触らない。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * 今フェーズで公開する7ページの定義。
 *
 * @return array<string,array{title:string,order:int,nav:bool}>
 */
function seizo_site_pages() {
	return array(
		'home'    => array( 'title' => 'ホーム', 'order' => 1, 'nav' => false ),
		'company' => array( 'title' => '会社概要', 'order' => 2, 'nav' => true ),
		'business' => array( 'title' => '事業・製品', 'order' => 3, 'nav' => true ),
		'quality' => array( 'title' => '品質・技術', 'order' => 4, 'nav' => true ),
		'recruit' => array( 'title' => '採用情報', 'order' => 5, 'nav' => true ),
		'contact' => array( 'title' => 'お問い合わせ', 'order' => 6, 'nav' => true ),
		'privacy' => array( 'title' => '個人情報保護方針', 'order' => 7, 'nav' => false ),
	);
}

/**
 * 有効化時の処理。
 */
function seizo_provision() {
	$ids = array();

	foreach ( seizo_site_pages() as $slug => $page ) {
		$existing = get_page_by_path( $slug );

		if ( $existing instanceof WP_Post ) {
			$ids[ $slug ] = $existing->ID;
			continue;
		}

		$id = wp_insert_post(
			array(
				'post_title'   => $page['title'],
				'post_name'    => $slug,
				'post_type'    => 'page',
				'post_status'  => 'publish',
				'menu_order'   => $page['order'],
				'post_content' => '',
			)
		);

		if ( ! is_wp_error( $id ) ) {
			$ids[ $slug ] = $id;
		}
	}

	// トップページを固定ページに切り替える。
	if ( isset( $ids['home'] ) ) {
		update_option( 'show_on_front', 'page' );
		update_option( 'page_on_front', $ids['home'] );
	}

	seizo_seed_news_categories();
	seizo_provision_menus( $ids );

	// お知らせのパーマリンクを有効にする。
	seizo_register_news();
	flush_rewrite_rules();
}
add_action( 'after_switch_theme', 'seizo_provision' );

/**
 * グローバルナビとフッターナビを組む。
 *
 * @param array<string,int> $ids スラッグ => 固定ページ ID。
 */
function seizo_provision_menus( array $ids ) {
	$locations = get_theme_mod( 'nav_menu_locations', array() );

	// --- グローバルナビ ---
	$primary = wp_get_nav_menu_object( 'グローバルナビ' );

	if ( ! $primary ) {
		$menu_id = wp_create_nav_menu( 'グローバルナビ' );

		if ( ! is_wp_error( $menu_id ) ) {
			foreach ( seizo_site_pages() as $slug => $page ) {
				if ( ! $page['nav'] || ! isset( $ids[ $slug ] ) ) {
					continue;
				}

				// 事業・製品の手前にお知らせを差し込む。
				if ( 'quality' === $slug ) {
					wp_update_nav_menu_item(
						$menu_id,
						0,
						array(
							'menu-item-title'     => 'お知らせ',
							'menu-item-url'       => home_url( '/news/' ),
							'menu-item-status'    => 'publish',
							'menu-item-position'  => $page['order'],
						)
					);
				}

				wp_update_nav_menu_item(
					$menu_id,
					0,
					array(
						'menu-item-object-id' => $ids[ $slug ],
						'menu-item-object'    => 'page',
						'menu-item-type'      => 'post_type',
						'menu-item-title'     => $page['title'],
						'menu-item-status'    => 'publish',
						'menu-item-position'  => $page['order'] + 1,
					)
				);
			}

			$locations['primary'] = $menu_id;
		}
	}

	// --- フッターナビ ---
	$footer = wp_get_nav_menu_object( 'フッターナビ' );

	if ( ! $footer ) {
		$footer_id = wp_create_nav_menu( 'フッターナビ' );

		if ( ! is_wp_error( $footer_id ) ) {
			foreach ( array( 'company', 'business', 'quality', 'recruit', 'contact', 'privacy' ) as $position => $slug ) {
				if ( ! isset( $ids[ $slug ] ) ) {
					continue;
				}

				wp_update_nav_menu_item(
					$footer_id,
					0,
					array(
						'menu-item-object-id' => $ids[ $slug ],
						'menu-item-object'    => 'page',
						'menu-item-type'      => 'post_type',
						'menu-item-title'     => get_the_title( $ids[ $slug ] ),
						'menu-item-status'    => 'publish',
						'menu-item-position'  => $position + 1,
					)
				);
			}

			$locations['footer'] = $footer_id;
		}
	}

	set_theme_mod( 'nav_menu_locations', $locations );
}
