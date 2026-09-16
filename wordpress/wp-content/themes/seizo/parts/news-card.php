<?php
/**
 * お知らせ1件分のカード。一覧・トップページで共用する。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$term = seizo_news_category();
?>
<article class="c-news-card">
	<a class="c-news-card__link" href="<?php the_permalink(); ?>">
		<div class="c-news-card__thumb">
			<?php if ( has_post_thumbnail() ) : ?>
				<?php the_post_thumbnail( 'seizo_news_card', array( 'loading' => 'lazy', 'alt' => '' ) ); ?>
			<?php else : ?>
				<span class="c-news-card__thumb-placeholder" aria-hidden="true"></span>
			<?php endif; ?>
		</div>

		<div class="c-news-card__body">
			<p class="c-news-card__meta">
				<time class="c-news-card__date" datetime="<?php echo esc_attr( get_the_date( 'c' ) ); ?>">
					<?php echo esc_html( seizo_news_date() ); ?>
				</time>
				<?php if ( $term ) : ?>
					<span class="c-news-card__cat c-news-card__cat--<?php echo esc_attr( $term->slug ); ?>">
						<?php echo esc_html( $term->name ); ?>
					</span>
				<?php endif; ?>
			</p>

			<h3 class="c-news-card__title"><?php the_title(); ?></h3>
			<p class="c-news-card__excerpt"><?php echo esc_html( seizo_news_excerpt() ); ?></p>
		</div>
	</a>
</article>
