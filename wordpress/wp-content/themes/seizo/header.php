<?php
/**
 * 共通ヘッダー。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="format-detection" content="telephone=no">
	<link rel="profile" href="https://gmpg.org/xfn/11">
	<?php wp_head(); ?>
</head>

<body <?php body_class(); ?>>
<?php wp_body_open(); ?>

<a class="c-skip-link u-visually-hidden" href="#main">本文へスキップ</a>

<header class="l-header" id="header">
	<div class="l-header__inner">
		<div class="l-header__brand">
			<?php $company = seizo_company(); ?>
			<a href="<?php echo esc_url( home_url( '/' ) ); ?>" class="l-header__logo">
				<?php if ( has_custom_logo() ) : ?>
					<?php the_custom_logo(); ?>
				<?php else : ?>
					<span class="l-header__logo-text"><?php echo esc_html( $company['name'] ); ?></span>
				<?php endif; ?>
			</a>
			<p class="l-header__tagline">確かな加工技術で、<?php echo esc_html( $company['founded'] ); ?>年から。</p>
		</div>

		<nav class="l-nav" id="global-nav" aria-label="グローバルナビゲーション">
			<?php
			wp_nav_menu(
				array(
					'theme_location' => 'primary',
					'container'      => false,
					'menu_class'     => 'l-nav__list',
					'depth'          => 2,
					'fallback_cb'    => 'seizo_nav_fallback',
				)
			);
			?>

			<div class="l-nav__actions">
				<p class="l-nav__tel">
					<span class="l-nav__tel-label">お電話でのお問い合わせ</span>
					<a href="tel:<?php echo esc_attr( str_replace( '-', '', $company['tel'] ) ); ?>">
						<?php echo esc_html( $company['tel'] ); ?>
					</a>
					<span class="l-nav__tel-hours"><?php echo esc_html( $company['hours'] ); ?></span>
				</p>
				<a class="c-button c-button--primary l-nav__cta" href="<?php echo esc_url( home_url( '/contact/' ) ); ?>">
					お問い合わせ
				</a>
			</div>
		</nav>

		<button
			type="button"
			class="l-header__toggle"
			id="nav-toggle"
			aria-controls="global-nav"
			aria-expanded="false"
		>
			<span class="l-header__toggle-bar" aria-hidden="true"></span>
			<span class="u-visually-hidden">メニューを開く</span>
		</button>
	</div>
</header>

<main id="main" class="l-main">
