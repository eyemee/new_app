<?php
/**
 * 共通フッター。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$company = seizo_company();
?>
</main><!-- /.l-main -->

<footer class="l-footer">
	<div class="l-footer__cta">
		<div class="l-container">
			<p class="l-footer__cta-lead">製品・加工に関するご相談はお気軽にどうぞ</p>
			<div class="l-footer__cta-actions">
				<a class="c-button c-button--primary c-button--lg" href="<?php echo esc_url( home_url( '/contact/' ) ); ?>">
					お問い合わせフォーム
				</a>
				<p class="l-footer__cta-tel">
					<a href="tel:<?php echo esc_attr( str_replace( '-', '', $company['tel'] ) ); ?>">
						<?php echo esc_html( $company['tel'] ); ?>
					</a>
					<span><?php echo esc_html( $company['hours'] ); ?></span>
				</p>
			</div>
		</div>
	</div>

	<div class="l-footer__body">
		<div class="l-container l-footer__grid">
			<div class="l-footer__company">
				<p class="l-footer__name"><?php echo esc_html( $company['name'] ); ?></p>
				<address class="l-footer__address">
					<?php echo esc_html( $company['zip'] ); ?><br>
					<?php echo esc_html( $company['address'] ); ?><br>
					TEL <?php echo esc_html( $company['tel'] ); ?> / FAX <?php echo esc_html( $company['fax'] ); ?>
				</address>
			</div>

			<nav class="l-footer__nav" aria-label="フッターナビゲーション">
				<?php
				wp_nav_menu(
					array(
						'theme_location' => 'footer',
						'container'      => false,
						'menu_class'     => 'l-footer__list',
						'depth'          => 1,
						'fallback_cb'    => 'seizo_nav_fallback',
					)
				);
				?>
			</nav>
		</div>
	</div>

	<div class="l-footer__bottom">
		<div class="l-container">
			<p class="l-footer__copy">
				&copy; <?php echo esc_html( gmdate( 'Y' ) ); ?> <?php echo esc_html( $company['name_en'] ); ?>
			</p>
		</div>
	</div>
</footer>

<button type="button" class="c-pagetop" id="pagetop">
	<span class="u-visually-hidden">ページ上部へ戻る</span>
</button>

<?php wp_footer(); ?>
</body>
</html>
