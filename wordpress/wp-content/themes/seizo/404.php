<?php
/**
 * 404。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

seizo_page_hero( 'ページが見つかりません', '404' );
?>

<section class="p-404">
	<div class="l-container l-container--narrow">
		<p class="p-404__lead">
			お探しのページは、移動または削除された可能性があります。<br>
			お手数ですが、以下のリンクからお探しください。
		</p>

		<ul class="p-404__links">
			<li><a href="<?php echo esc_url( home_url( '/' ) ); ?>">トップページ</a></li>
			<li><a href="<?php echo esc_url( home_url( '/business/' ) ); ?>">事業・製品</a></li>
			<li><a href="<?php echo esc_url( get_post_type_archive_link( 'news' ) ); ?>">お知らせ</a></li>
			<li><a href="<?php echo esc_url( home_url( '/contact/' ) ); ?>">お問い合わせ</a></li>
		</ul>
	</div>
</section>

<?php
get_footer();
