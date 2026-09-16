<?php
/**
 * トップページ。
 *
 * ★入稿デザイン対応: セクション順は AI の並び（キービジュアル → 事業紹介 →
 * 強み → お知らせ → 会社情報）に合わせている。文言は仮のため、確定原稿が
 * 来たら差し替える。構造とクラス名は変えずに済むように組んでいる。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

$company = seizo_company();
$news    = seizo_recent_news( 4 );
?>

<section class="p-hero">
	<div class="p-hero__inner">
		<div class="p-hero__copy">
			<p class="p-hero__label">SINCE <?php echo esc_html( $company['founded'] ); ?> / NAGOYA</p>
			<h1 class="p-hero__title">
				<span>削る、磨く、仕上げる。</span>
				<span>その精度が、次をつくる。</span>
			</h1>
			<p class="p-hero__lead">
				<?php echo esc_html( $company['founded'] ); ?>年の創業以来、名古屋で金属加工に取り組んできました。
				試作から量産まで、図面の一本の線に応える体制があります。
			</p>
			<div class="p-hero__actions">
				<a class="c-button c-button--primary c-button--lg" href="<?php echo esc_url( home_url( '/business/' ) ); ?>">
					事業・製品を見る
				</a>
				<a class="c-button c-button--ghost c-button--lg" href="<?php echo esc_url( home_url( '/contact/' ) ); ?>">
					お問い合わせ
				</a>
			</div>
		</div>

		<div class="p-hero__visual">
			<!-- ★入稿差し替え: キービジュアル。AI の書き出し（@2x / WebP）を assets/img/ に置く -->
			<img
				src="<?php echo esc_url( SEIZO_URI . '/assets/img/hero.jpg' ); ?>"
				alt=""
				width="1600"
				height="1000"
				fetchpriority="high"
			>
		</div>
	</div>
</section>

<section class="p-home-business">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">事業内容</h2>
			<p class="c-section-head__en">OUR BUSINESS</p>
		</header>

		<ul class="p-home-business__list">
			<?php
			$business = array(
				array(
					'title' => '精密機械加工',
					'text'  => 'マシニングセンタと NC 旋盤による、単品から中量産まで。公差の厳しい部品ほど得意としています。',
					'img'   => 'business-01.jpg',
				),
				array(
					'title' => '金型設計・製作',
					'text'  => '設計から製作、トライ、量産立ち上げまでを社内で一貫。立ち上げ後の改良にも対応します。',
					'img'   => 'business-02.jpg',
				),
				array(
					'title' => '試作・開発支援',
					'text'  => '図面が固まる前の段階からご相談ください。加工しやすい形状のご提案を含めて対応します。',
					'img'   => 'business-03.jpg',
				),
			);

			foreach ( $business as $item ) :
				?>
				<li class="p-home-business__item">
					<div class="p-home-business__thumb">
						<img
							src="<?php echo esc_url( SEIZO_URI . '/assets/img/' . $item['img'] ); ?>"
							alt=""
							width="800"
							height="600"
							loading="lazy"
						>
					</div>
					<h3 class="p-home-business__title"><?php echo esc_html( $item['title'] ); ?></h3>
					<p class="p-home-business__text"><?php echo esc_html( $item['text'] ); ?></p>
				</li>
			<?php endforeach; ?>
		</ul>

		<p class="p-home-business__more">
			<a class="c-button c-button--ghost" href="<?php echo esc_url( home_url( '/business/' ) ); ?>">
				事業・製品の詳細
			</a>
		</p>
	</div>
</section>

<section class="p-home-strength">
	<div class="l-container">
		<header class="c-section-head c-section-head--light">
			<h2 class="c-section-head__title">選ばれる理由</h2>
			<p class="c-section-head__en">OUR STRENGTH</p>
		</header>

		<dl class="p-home-strength__list">
			<div class="p-home-strength__item">
				<dt class="p-home-strength__num">01</dt>
				<dd>
					<h3><?php echo esc_html( $company['founded'] ); ?>年創業の蓄積</h3>
					<p>60年以上にわたって積み上げた加工条件と段取りのノウハウが、立ち上げの速さにつながっています。</p>
				</dd>
			</div>
			<div class="p-home-strength__item">
				<dt class="p-home-strength__num">02</dt>
				<dd>
					<h3>一貫対応</h3>
					<p>設計・製作・検査までを社内で完結。工程間の受け渡しで生じる手戻りを抑えます。</p>
				</dd>
			</div>
			<div class="p-home-strength__item">
				<dt class="p-home-strength__num">03</dt>
				<dd>
					<h3>品質保証体制</h3>
					<p>三次元測定機による全数・抜取検査に対応。検査成績書の発行も承ります。</p>
				</dd>
			</div>
		</dl>
	</div>
</section>

<section class="p-home-news">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">お知らせ</h2>
			<p class="c-section-head__en">NEWS</p>
		</header>

		<?php if ( $news ) : ?>
			<div class="p-home-news__list">
				<?php
				global $post;
				foreach ( $news as $post ) :
					setup_postdata( $post );
					get_template_part( 'parts/news-card' );
				endforeach;
				wp_reset_postdata();
				?>
			</div>

			<p class="p-home-news__more">
				<a class="c-button c-button--ghost" href="<?php echo esc_url( get_post_type_archive_link( 'news' ) ); ?>">
					お知らせ一覧
				</a>
			</p>
		<?php else : ?>
			<p class="p-home-news__empty">お知らせはまだありません。</p>
		<?php endif; ?>
	</div>
</section>

<section class="p-home-company">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">会社概要</h2>
			<p class="c-section-head__en">COMPANY</p>
		</header>

		<div class="p-home-company__inner">
			<dl class="p-home-company__table">
				<div><dt>会社名</dt><dd><?php echo esc_html( $company['name'] ); ?></dd></div>
				<div><dt>創業</dt><dd><?php echo esc_html( $company['founded'] ); ?>年</dd></div>
				<div><dt>所在地</dt><dd><?php echo esc_html( $company['zip'] . ' ' . $company['address'] ); ?></dd></div>
			</dl>

			<p class="p-home-company__more">
				<a class="c-button c-button--ghost" href="<?php echo esc_url( home_url( '/company/' ) ); ?>">
					会社概要の詳細
				</a>
			</p>
		</div>
	</div>
</section>

<?php
get_footer();
