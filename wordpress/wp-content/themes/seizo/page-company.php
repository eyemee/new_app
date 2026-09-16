<?php
/**
 * 会社概要。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

$company = seizo_company();

seizo_page_hero( '会社概要', 'COMPANY' );
seizo_breadcrumb( array( array( 'label' => '会社概要' ) ) );
?>

<section class="p-company-message">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">ごあいさつ</h2>
			<p class="c-section-head__en">MESSAGE</p>
		</header>

		<div class="p-company-message__inner">
			<div class="p-company-message__text">
				<!-- ★要差し替え: 代表メッセージ。クライアント支給原稿に置き換える -->
				<p>
					当社は<?php echo esc_html( $company['founded'] ); ?>年、名古屋の地で小さな町工場として歩みを始めました。
					以来一貫して、図面に書かれた精度を確実に形にすることに向き合ってきました。
				</p>
				<p>
					設備は変わり、扱う材料も変わりましたが、一つひとつの仕事に責任を持つという姿勢は創業時から変えていません。
					これからも、お客様の「こういうものが作れないか」という相談に、技術で応えてまいります。
				</p>
				<p class="p-company-message__sign">
					<?php echo esc_html( $company['name'] ); ?><br>
					代表取締役　◯◯　◯◯
				</p>
			</div>

			<div class="p-company-message__photo">
				<img
					src="<?php echo esc_url( SEIZO_URI . '/assets/img/president.jpg' ); ?>"
					alt=""
					width="720"
					height="900"
					loading="lazy"
				>
			</div>
		</div>
	</div>
</section>

<section class="p-company-outline">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">会社概要</h2>
			<p class="c-section-head__en">OUTLINE</p>
		</header>

		<dl class="c-definition">
			<?php
			// ★要差し替え: 確定情報に置き換える。項目の増減はこの配列だけで済む。
			$outline = array(
				'会社名'   => $company['name'],
				'英文社名' => $company['name_en'],
				'創業'     => $company['founded'] . '年',
				'設立'     => '1962年4月',
				'資本金'   => '3,000万円',
				'代表者'   => '代表取締役　◯◯　◯◯',
				'従業員数' => '48名（2025年4月現在）',
				'所在地'   => $company['zip'] . '　' . $company['address'],
				'連絡先'   => 'TEL ' . $company['tel'] . '　/　FAX ' . $company['fax'],
				'事業内容' => '精密機械加工、金型設計・製作、試作開発支援',
				'取引銀行' => '◯◯銀行 ◯◯支店 / ◯◯信用金庫 ◯◯支店',
			);

			foreach ( $outline as $label => $value ) :
				?>
				<div class="c-definition__row">
					<dt class="c-definition__label"><?php echo esc_html( $label ); ?></dt>
					<dd class="c-definition__value"><?php echo esc_html( $value ); ?></dd>
				</div>
			<?php endforeach; ?>
		</dl>
	</div>
</section>

<section class="p-company-history">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">沿革</h2>
			<p class="c-section-head__en">HISTORY</p>
		</header>

		<ol class="c-history">
			<?php
			// ★要差し替え: 沿革。年表の行数は自由に増やせる。
			$history = array(
				'1958年' => '名古屋市中区にて創業。旋盤加工を開始。',
				'1962年' => '株式会社に改組。',
				'1975年' => '本社工場を増築、フライス加工部門を新設。',
				'1988年' => 'NC 旋盤を導入し、量産対応を本格化。',
				'2002年' => '金型設計・製作部門を新設。',
				'2011年' => '三次元測定機を導入、検査体制を強化。',
				'2019年' => '第二工場を竣工。マシニングセンタを増設。',
			);

			foreach ( $history as $year => $event ) :
				?>
				<li class="c-history__item">
					<span class="c-history__year"><?php echo esc_html( $year ); ?></span>
					<span class="c-history__event"><?php echo esc_html( $event ); ?></span>
				</li>
			<?php endforeach; ?>
		</ol>
	</div>
</section>

<section class="p-company-access">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">アクセス</h2>
			<p class="c-section-head__en">ACCESS</p>
		</header>

		<div class="p-company-access__inner">
			<div class="p-company-access__map">
				<!-- ★要差し替え: Google マップの埋め込み URL を確定住所のものにする -->
				<iframe
					src="https://www.google.com/maps?q=%E5%90%8D%E5%8F%A4%E5%B1%8B%E5%B8%82%E4%B8%AD%E5%8C%BA%E6%A0%84&output=embed"
					width="100%"
					height="400"
					style="border:0;"
					loading="lazy"
					referrerpolicy="no-referrer-when-downgrade"
					title="所在地の地図"
				></iframe>
			</div>

			<div class="p-company-access__info">
				<p class="p-company-access__address">
					<?php echo esc_html( $company['zip'] ); ?><br>
					<?php echo esc_html( $company['address'] ); ?>
				</p>
				<dl class="c-definition c-definition--compact">
					<div class="c-definition__row">
						<dt class="c-definition__label">電車</dt>
						<dd class="c-definition__value">地下鉄◯◯線「◯◯」駅 ◯番出口より徒歩8分</dd>
					</div>
					<div class="c-definition__row">
						<dt class="c-definition__label">お車</dt>
						<dd class="c-definition__value">◯◯自動車道「◯◯IC」より約15分（駐車場10台）</dd>
					</div>
				</dl>
			</div>
		</div>
	</div>
</section>

<?php
get_footer();
