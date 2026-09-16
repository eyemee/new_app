<?php
/**
 * 採用情報。
 *
 * 募集要項の更新は今フェーズの CMS 化対象外（お知らせのみ）。
 * 内容の更新は「お知らせ」に採用カテゴリーで投稿する運用を想定し、
 * このページの下部に採用カテゴリーの投稿を自動で出している。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

$company = seizo_company();

seizo_page_hero( '採用情報', 'RECRUIT' );
seizo_breadcrumb( array( array( 'label' => '採用情報' ) ) );
?>

<section class="p-recruit-message">
	<div class="l-container">
		<p class="p-recruit-message__lead">
			ものづくりの現場で、長く働ける場所を。
		</p>
		<p class="p-recruit-message__text">
			<!-- ★要差し替え: 採用メッセージ -->
			当社の平均勤続年数は14年です。未経験から入社して、いまは工程設計を任されている社員もいます。
			手を動かして覚えたい方、図面を読めるようになりたい方を歓迎します。
		</p>
	</div>
</section>

<section class="p-recruit-positions">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">募集要項</h2>
			<p class="c-section-head__en">POSITIONS</p>
		</header>

		<?php
		// ★要差し替え: 募集要項。募集停止時はこの配列から外す。
		$positions = array(
			array(
				'title'  => '機械加工オペレーター（正社員）',
				'detail' => array(
					'仕事内容' => 'マシニングセンタ・NC 旋盤の段取りと加工、工程内検査',
					'応募資格' => '未経験可（工業高校卒・機械加工経験者は優遇）',
					'勤務地'   => $company['address'],
					'勤務時間' => '8:00〜17:00（休憩60分）',
					'給与'     => '月給21万円〜32万円（経験・能力を考慮）',
					'休日'     => '完全週休2日制（土日）、祝日、夏季、年末年始',
					'待遇'     => '各種社会保険完備、交通費支給、資格取得支援、退職金制度',
				),
			),
			array(
				'title'  => '生産技術・工程設計（正社員）',
				'detail' => array(
					'仕事内容' => '加工工程の設計、治具設計、原価計算、量産立ち上げ',
					'応募資格' => '機械加工または生産技術の実務経験3年以上',
					'勤務地'   => $company['address'],
					'勤務時間' => '8:00〜17:00（休憩60分）',
					'給与'     => '月給26万円〜40万円（経験・能力を考慮）',
					'休日'     => '完全週休2日制（土日）、祝日、夏季、年末年始',
					'待遇'     => '各種社会保険完備、交通費支給、資格取得支援、退職金制度',
				),
			),
		);

		foreach ( $positions as $position ) :
			?>
			<article class="p-recruit-position">
				<h3 class="p-recruit-position__title"><?php echo esc_html( $position['title'] ); ?></h3>

				<dl class="c-definition">
					<?php foreach ( $position['detail'] as $label => $value ) : ?>
						<div class="c-definition__row">
							<dt class="c-definition__label"><?php echo esc_html( $label ); ?></dt>
							<dd class="c-definition__value"><?php echo esc_html( $value ); ?></dd>
						</div>
					<?php endforeach; ?>
				</dl>
			</article>
		<?php endforeach; ?>

		<div class="p-recruit-positions__cta">
			<p>ご応募・ご質問はお問い合わせフォームより承ります。</p>
			<a class="c-button c-button--primary c-button--lg" href="<?php echo esc_url( add_query_arg( 'subject', 'recruit', home_url( '/contact/' ) ) ); ?>">
				応募・お問い合わせ
			</a>
		</div>
	</div>
</section>

<?php
// 採用カテゴリーのお知らせがあれば表示する。
$recruit_news = get_posts(
	array(
		'post_type'      => 'news',
		'posts_per_page' => 3,
		'tax_query'      => array(
			array(
				'taxonomy' => 'news_category',
				'field'    => 'slug',
				'terms'    => 'recruit',
			),
		),
	)
);

if ( $recruit_news ) :
	?>
	<section class="p-recruit-news">
		<div class="l-container">
			<header class="c-section-head">
				<h2 class="c-section-head__title">採用に関するお知らせ</h2>
				<p class="c-section-head__en">NEWS</p>
			</header>

			<div class="p-recruit-news__list">
				<?php
				global $post;
				foreach ( $recruit_news as $post ) :
					setup_postdata( $post );
					get_template_part( 'parts/news-card' );
				endforeach;
				wp_reset_postdata();
				?>
			</div>
		</div>
	</section>
	<?php
endif;

get_footer();
