<?php
/**
 * 品質・技術。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

seizo_page_hero( '品質・技術', 'QUALITY' );
seizo_breadcrumb( array( array( 'label' => '品質・技術' ) ) );
?>

<section class="p-quality-policy">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">品質方針</h2>
			<p class="c-section-head__en">POLICY</p>
		</header>

		<!-- ★要差し替え: 品質方針の正式文言 -->
		<p class="p-quality-policy__lead">
			「図面どおりに、期日どおりに」を当たり前に続けること。<br>
			それが、お客様の生産計画を止めない唯一の方法だと考えています。
		</p>

		<ul class="p-quality-policy__list">
			<li>
				<h3>全数・抜取検査の使い分け</h3>
				<p>製品の用途とロットに応じて検査方式を設定し、検査基準書として記録に残します。</p>
			</li>
			<li>
				<h3>トレーサビリティの確保</h3>
				<p>材料ロットから加工者、検査者までを紐づけて管理。問題発生時に遡れる状態を保ちます。</p>
			</li>
			<li>
				<h3>是正処置の標準化</h3>
				<p>不具合は原因を工程まで遡って特定し、作業標準の更新までを1件ごとに完了させます。</p>
			</li>
		</ul>
	</div>
</section>

<section class="p-quality-flow">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">生産の流れ</h2>
			<p class="c-section-head__en">PROCESS</p>
		</header>

		<ol class="c-flow">
			<?php
			$flow = array(
				array( 'title' => 'お問い合わせ・お見積り', 'text' => '図面またはご要望をお送りください。2営業日以内にお見積りをご返送します。' ),
				array( 'title' => '仕様打ち合わせ', 'text' => '材質・公差・数量・納期を確認し、加工方法をご提案します。' ),
				array( 'title' => '工程設計・段取り', 'text' => '加工順序と治具を設計。必要に応じて試作で条件を詰めます。' ),
				array( 'title' => '加工', 'text' => 'マシニングセンタ・NC 旋盤で加工。工程内検査を並行して行います。' ),
				array( 'title' => '検査', 'text' => '三次元測定機による寸法検査。検査成績書の発行も承ります。' ),
				array( 'title' => '出荷', 'text' => '梱包仕様のご指定に対応。納期どおりの出荷を徹底します。' ),
			);

			foreach ( $flow as $index => $step ) :
				?>
				<li class="c-flow__item">
					<span class="c-flow__num"><?php echo esc_html( sprintf( '%02d', $index + 1 ) ); ?></span>
					<div class="c-flow__body">
						<h3 class="c-flow__title"><?php echo esc_html( $step['title'] ); ?></h3>
						<p class="c-flow__text"><?php echo esc_html( $step['text'] ); ?></p>
					</div>
				</li>
			<?php endforeach; ?>
		</ol>
	</div>
</section>

<section class="p-quality-equipment">
	<div class="l-container">
		<header class="c-section-head">
			<h2 class="c-section-head__title">主要設備</h2>
			<p class="c-section-head__en">EQUIPMENT</p>
		</header>

		<div class="c-table-scroll">
			<table class="c-table">
				<thead>
					<tr>
						<th scope="col">設備名</th>
						<th scope="col">メーカー・型式</th>
						<th scope="col">台数</th>
						<th scope="col">加工能力</th>
					</tr>
				</thead>
				<tbody>
					<?php
					// ★要差し替え: 設備一覧。クライアント支給の設備台帳に置き換える。
					$equipment = array(
						array( '立形マシニングセンタ', '◯◯社 V-◯◯◯', '6台', '800 × 500 × 450mm' ),
						array( '横形マシニングセンタ', '◯◯社 H-◯◯◯', '2台', '630 × 630 × 630mm' ),
						array( 'NC 旋盤', '◯◯社 L-◯◯◯', '5台', 'φ350 × 600mm' ),
						array( '汎用フライス盤', '◯◯社', '3台', '—' ),
						array( '三次元測定機', '◯◯社 CMM-◯◯', '1台', '700 × 700 × 600mm' ),
						array( '表面粗さ測定機', '◯◯社', '1台', '—' ),
					);

					foreach ( $equipment as $row ) :
						?>
						<tr>
							<th scope="row"><?php echo esc_html( $row[0] ); ?></th>
							<td><?php echo esc_html( $row[1] ); ?></td>
							<td><?php echo esc_html( $row[2] ); ?></td>
							<td><?php echo esc_html( $row[3] ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>
</section>

<?php
get_footer();
