<?php
/**
 * お知らせ一覧（アーカイブ / カテゴリー）。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

$current_term = is_tax( 'news_category' ) ? get_queried_object() : null;
$title        = $current_term ? $current_term->name : 'お知らせ';

seizo_page_hero( $title, 'NEWS' );

$trail = array();
if ( $current_term ) {
	$trail[] = array( 'label' => 'お知らせ', 'url' => get_post_type_archive_link( 'news' ) );
	$trail[] = array( 'label' => $current_term->name );
} else {
	$trail[] = array( 'label' => 'お知らせ' );
}
seizo_breadcrumb( $trail );

$terms = get_terms(
	array(
		'taxonomy'   => 'news_category',
		'hide_empty' => true,
	)
);
?>

<section class="p-news">
	<div class="l-container">

		<?php if ( ! is_wp_error( $terms ) && $terms ) : ?>
			<nav class="c-filter" aria-label="カテゴリーで絞り込み">
				<ul class="c-filter__list">
					<li class="c-filter__item">
						<a
							class="c-filter__link <?php echo $current_term ? '' : 'is-current'; ?>"
							href="<?php echo esc_url( get_post_type_archive_link( 'news' ) ); ?>"
						>すべて</a>
					</li>
					<?php foreach ( $terms as $term ) : ?>
						<li class="c-filter__item">
							<a
								class="c-filter__link <?php echo ( $current_term && $current_term->term_id === $term->term_id ) ? 'is-current' : ''; ?>"
								href="<?php echo esc_url( get_term_link( $term ) ); ?>"
							><?php echo esc_html( $term->name ); ?></a>
						</li>
					<?php endforeach; ?>
				</ul>
			</nav>
		<?php endif; ?>

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
			<p class="p-news__empty">該当するお知らせはまだありません。</p>
		<?php endif; ?>

	</div>
</section>

<?php
get_footer();
