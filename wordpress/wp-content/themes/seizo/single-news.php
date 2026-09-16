<?php
/**
 * お知らせ詳細。
 *
 * 本文はクライアントがブロックエディタで編集する唯一の領域。
 * the_content() の出力に対して assets/css/pages.css の .p-news-detail__body 側で
 * 見出し・段落・リスト・画像のスタイルを当てている。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

while ( have_posts() ) :
	the_post();

	$term = seizo_news_category();

	seizo_page_hero( 'お知らせ', 'NEWS' );

	$trail = array( array( 'label' => 'お知らせ', 'url' => get_post_type_archive_link( 'news' ) ) );
	if ( $term ) {
		$trail[] = array( 'label' => $term->name, 'url' => get_term_link( $term ) );
	}
	$trail[] = array( 'label' => get_the_title() );
	seizo_breadcrumb( $trail );
	?>

	<article class="p-news-detail">
		<div class="l-container l-container--narrow">
			<header class="p-news-detail__head">
				<p class="p-news-detail__meta">
					<time datetime="<?php echo esc_attr( get_the_date( 'c' ) ); ?>">
						<?php echo esc_html( seizo_news_date() ); ?>
					</time>
					<?php if ( $term ) : ?>
						<span class="c-news-card__cat c-news-card__cat--<?php echo esc_attr( $term->slug ); ?>">
							<?php echo esc_html( $term->name ); ?>
						</span>
					<?php endif; ?>
				</p>
				<h1 class="p-news-detail__title"><?php the_title(); ?></h1>
			</header>

			<?php if ( has_post_thumbnail() ) : ?>
				<div class="p-news-detail__thumb">
					<?php the_post_thumbnail( 'seizo_news_hero', array( 'alt' => '' ) ); ?>
				</div>
			<?php endif; ?>

			<div class="p-news-detail__body">
				<?php the_content(); ?>
			</div>

			<?php
			$prev = get_previous_post();
			$next = get_next_post();
			?>
			<nav class="c-post-nav" aria-label="前後のお知らせ">
				<div class="c-post-nav__side">
					<?php if ( $prev ) : ?>
						<a class="c-post-nav__link c-post-nav__link--prev" href="<?php echo esc_url( get_permalink( $prev ) ); ?>">
							<span class="c-post-nav__label">前のお知らせ</span>
							<span class="c-post-nav__title"><?php echo esc_html( get_the_title( $prev ) ); ?></span>
						</a>
					<?php endif; ?>
				</div>

				<p class="c-post-nav__index">
					<a class="c-button c-button--ghost" href="<?php echo esc_url( get_post_type_archive_link( 'news' ) ); ?>">
						一覧へ戻る
					</a>
				</p>

				<div class="c-post-nav__side c-post-nav__side--next">
					<?php if ( $next ) : ?>
						<a class="c-post-nav__link c-post-nav__link--next" href="<?php echo esc_url( get_permalink( $next ) ); ?>">
							<span class="c-post-nav__label">次のお知らせ</span>
							<span class="c-post-nav__title"><?php echo esc_html( get_the_title( $next ) ); ?></span>
						</a>
					<?php endif; ?>
				</div>
			</nav>
		</div>
	</article>

	<?php
endwhile;

get_footer();
