<?php
/**
 * 管理画面の調整。
 *
 * 今フェーズでクライアントが触るのは「お知らせ」だけ。管理画面に今回使わない
 * 導線が並んでいると誤操作のもとになるので、権限に応じて絞り込む。
 * 管理者（manage_options 保持者）には制限をかけない。開発・保守で必要なため。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * クライアント向けに管理メニューを絞る。
 */
function seizo_trim_admin_menu() {
	// 標準の「投稿」は使わない（お知らせは専用投稿タイプ）。全ユーザーで隠す。
	remove_menu_page( 'edit.php' );
	remove_menu_page( 'edit-comments.php' );

	if ( current_user_can( 'manage_options' ) ) {
		return;
	}

	// 固定ページはテンプレート側で組んでいるため、編集導線は出さない。
	remove_menu_page( 'edit.php?post_type=page' );
	remove_menu_page( 'tools.php' );
	remove_menu_page( 'themes.php' );
}
add_action( 'admin_menu', 'seizo_trim_admin_menu', 999 );

/**
 * 管理バーからも同様に外す。
 *
 * @param WP_Admin_Bar $bar 管理バー。
 */
function seizo_trim_admin_bar( $bar ) {
	$bar->remove_node( 'comments' );

	$new_content = $bar->get_node( 'new-post' );
	if ( $new_content ) {
		$bar->remove_node( 'new-post' );
	}
}
add_action( 'admin_bar_menu', 'seizo_trim_admin_bar', 999 );

/**
 * ダッシュボードに運用メモを出す。
 * 納品後、クライアント側の担当者が変わっても手順が残るようにしておく。
 */
function seizo_dashboard_widget() {
	wp_add_dashboard_widget(
		'seizo_guide',
		'お知らせの更新について',
		'seizo_dashboard_widget_render'
	);
}
add_action( 'wp_dashboard_setup', 'seizo_dashboard_widget' );

/**
 * 運用メモの中身。
 */
function seizo_dashboard_widget_render() {
	$new_url  = admin_url( 'post-new.php?post_type=news' );
	$list_url = admin_url( 'edit.php?post_type=news' );
	?>
	<p>サイトの更新は左メニューの「<strong>お知らせ</strong>」から行えます。</p>
	<ol style="padding-left:1.2em;line-height:1.9;">
		<li><a href="<?php echo esc_url( $new_url ); ?>">新規追加</a> を開き、タイトルと本文を入力します。</li>
		<li>右側の「カテゴリー」を1つ選びます（お知らせ／製品情報／採用情報／プレスリリース）。</li>
		<li>一覧に画像を出す場合は「アイキャッチ画像」を設定します（推奨 1280×720px）。</li>
		<li>「公開」を押すと、トップページと<a href="<?php echo esc_url( home_url( '/news/' ) ); ?>">お知らせ一覧</a>に自動で反映されます。</li>
	</ol>
	<p style="margin-bottom:0;">
		公開済みの記事を直すときは <a href="<?php echo esc_url( $list_url ); ?>">お知らせ一覧</a> から選んで編集し、「更新」を押してください。
	</p>
	<?php
}

/**
 * お知らせ一覧の列を運用しやすい並びにする。
 *
 * @param array<string,string> $columns 列定義。
 * @return array<string,string>
 */
function seizo_news_columns( $columns ) {
	$reordered = array();

	foreach ( $columns as $key => $label ) {
		if ( 'date' === $key ) {
			continue;
		}
		$reordered[ $key ] = $label;
	}

	$reordered['date'] = '公開日';

	return $reordered;
}
add_filter( 'manage_news_posts_columns', 'seizo_news_columns' );

/**
 * 管理画面のフッターに連絡先を出しておく。困ったときの導線。
 *
 * @param string $text 既定のテキスト。
 * @return string
 */
function seizo_admin_footer( $text ) {
	if ( current_user_can( 'manage_options' ) ) {
		return $text;
	}

	return 'サイトの表示や操作でご不明な点がありましたら、制作担当までご連絡ください。';
}
add_filter( 'admin_footer_text', 'seizo_admin_footer' );
