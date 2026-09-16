<?php
/**
 * フォールバックテンプレート。
 *
 * 通常の導線では使われない（トップ・固定ページ・お知らせに専用テンプレートがある）が、
 * WordPress のテンプレート階層上、存在が必須のため用意している。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

seizo_page_hero( is_search() ? '検索結果' : 'お知らせ' );
?>

<section class="p-news">
	<div class="l-container">
		<?php if ( have_posts() ) : ?>
			<div class="p-news__list">
				<?php
				while ( have_posts() ) :
					the_post();
					get_template_part( 'parts/news-card' );
				endwhile;
				?>
			</div>

			<?php seizo_pagination(); ?>
		<?php else : ?>
			<p class="p-news__empty">表示できる記事がありません。</p>
		<?php endif; ?>
	</div>
</section>

<?php
get_footer();
