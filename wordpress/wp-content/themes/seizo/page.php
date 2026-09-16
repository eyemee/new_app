<?php
/**
 * 固定ページの汎用テンプレート。
 *
 * 7ページはそれぞれ専用テンプレート（page-{slug}.php）を持つ。
 * これは個人情報保護方針のような、本文をそのまま流す下層ページ用。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

while ( have_posts() ) :
	the_post();

	seizo_page_hero( get_the_title() );
	seizo_breadcrumb( array( array( 'label' => get_the_title() ) ) );
	?>

	<section class="p-page">
		<div class="l-container l-container--narrow">
			<div class="p-page__body">
				<?php
				if ( '' !== trim( get_the_content() ) ) {
					the_content();
				} else {
					// 本文未入力のページでも骨組みが崩れないようにしておく。
					echo '<p>このページは準備中です。</p>';
				}
				?>
			</div>
		</div>
	</section>

	<?php
endwhile;

get_footer();
