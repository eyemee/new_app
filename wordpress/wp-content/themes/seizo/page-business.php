<?php
/**
 * 事業・製品。
 *
 * 製品一覧は今フェーズでは現行サイトへ送り出す（検索・絞り込みは次フェーズ）。
 * 遷移先が別サイトになることをユーザーに明示したうえでリンクする。
 * 移管時は seizo_company()['legacy_url'] を差し替えるか、下の $categories の
 * url を新しい製品ページに向けるだけで済むようにしてある。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

$company = seizo_company();
$legacy  = $company['legacy_url'];

seizo_page_hero( '事業・製品', 'BUSINESS' );
seizo_breadcrumb( array( array( 'label' => '事業・製品' ) ) );
?>

<section class="p-business-intro">
	<div class="l-container">
		<p class="p-business-intro__lead">
			試作から量産まで、金属加工にまつわる工程を一貫して承ります。<br>
			材質・数量・納期のご相談は、図面が固まる前の段階からお受けしています。
		</p>
	</div>
</section>

<section class="p-business-fields">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">事業内容</h2>
			<p class="c-section-head__en">FIELDS</p>
		</header>

		<?php
		$fields = array(
			array(
				'title' => '精密機械加工',
				'img'   => 'business-01.jpg',
				'text'  => 'マシニングセンタ・NC 旋盤による切削加工。単品試作から中量産まで、公差の厳しい部品に対応します。アルミ、ステンレス、鉄、樹脂など幅広い材質の加工実績があります。',
				'specs' => array(
					'対応サイズ' => '最大 800 × 500 × 450mm',
					'対応数量'   => '1個〜10,000個',
					'主な材質'   => 'アルミ / ステンレス / 鉄 / 樹脂',
				),
			),
			array(
				'title' => '金型設計・製作',
				'img'   => 'business-02.jpg',
				'text'  => '設計から製作、トライ、量産立ち上げまで社内一貫。立ち上げ後の形状変更や、既存金型の改修にも対応しています。',
				'specs' => array(
					'対応金型' => 'プレス金型 / 樹脂成形金型',
					'設計'     => '3D CAD（3次元設計）対応',
					'納期目安' => '小型金型で約4〜6週間',
				),
			),
			array(
				'title' => '試作・開発支援',
				'img'   => 'business-03.jpg',
				'text'  => '量産を見据えた形状のご提案を含めて対応します。「この形は加工できるか」という段階のご相談を歓迎します。',
				'specs' => array(
					'ご相談段階' => '構想・ポンチ絵から可',
					'ご提案内容' => '加工性改善 / コストダウン形状',
					'最短納期'   => '3営業日〜（数量・形状による）',
				),
			),
		);

		foreach ( $fields as $index => $field ) :
			?>
			<article class="p-business-field <?php echo 0 === $index % 2 ? '' : 'p-business-field--reverse'; ?>">
				<div class="p-business-field__visual">
					<img
						src="<?php echo esc_url( SEIZO_URI . '/assets/img/' . $field['img'] ); ?>"
						alt=""
						width="960"
						height="640"
						loading="lazy"
					>
				</div>

				<div class="p-business-field__body">
					<h3 class="p-business-field__title"><?php echo esc_html( $field['title'] ); ?></h3>
					<p class="p-business-field__text"><?php echo esc_html( $field['text'] ); ?></p>

					<dl class="c-definition c-definition--compact">
						<?php foreach ( $field['specs'] as $label => $value ) : ?>
							<div class="c-definition__row">
								<dt class="c-definition__label"><?php echo esc_html( $label ); ?></dt>
								<dd class="c-definition__value"><?php echo esc_html( $value ); ?></dd>
							</div>
						<?php endforeach; ?>
					</dl>
				</div>
			</article>
		<?php endforeach; ?>
	</div>
</section>

<section class="p-business-products">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">製品情報</h2>
			<p class="c-section-head__en">PRODUCTS</p>
		</header>

		<p class="p-business-products__note">
			製品の詳細・仕様は現行の製品サイトでご覧いただけます。
			<span class="p-business-products__note-sub">（リンクをクリックすると別サイトが開きます）</span>
		</p>

		<ul class="p-business-products__list">
			<?php
			// ★次フェーズで自社側の製品DBに差し替える想定。今は現行サイトへの導線のみ。
			$categories = array(
				array( 'label' => '標準部品', 'desc' => '規格品の一覧・寸法表', 'url' => $legacy . 'standard/' ),
				array( 'label' => '受注加工品', 'desc' => '加工事例と対応範囲', 'url' => $legacy . 'custom/' ),
				array( 'label' => '金型製品', 'desc' => '金型の種類と実績', 'url' => $legacy . 'mold/' ),
				array( 'label' => '製品カタログ', 'desc' => 'PDF カタログのダウンロード', 'url' => $legacy . 'catalog/' ),
			);

			foreach ( $categories as $category ) :
				?>
				<li class="p-business-products__item">
					<?php seizo_external_link( $category['url'], $category['label'], 'p-business-products__link' ); ?>
					<p class="p-business-products__desc"><?php echo esc_html( $category['desc'] ); ?></p>
				</li>
			<?php endforeach; ?>
		</ul>

		<p class="p-business-products__all">
			<?php seizo_external_link( $legacy, '製品一覧をすべて見る', 'c-button c-button--ghost' ); ?>
		</p>
	</div>
</section>

<?php
get_footer();
