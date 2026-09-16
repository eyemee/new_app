<?php
/**
 * お問い合わせ。
 *
 * 入力 → 確認 → 完了 の3画面を1テンプレートで出し分ける。
 * POST の処理と検証は inc/contact.php 側（template_redirect）で済んでおり、
 * ここは状態を受け取って描画するだけ。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();

$company = seizo_company();
$state   = seizo_contact_state();
$fields  = seizo_contact_fields();
$step    = $state['step'];
$values  = $state['values'];
$errors  = $state['errors'];

// 採用ページからの導線は種別を初期選択しておく。
if ( 'input' === $step && empty( $values ) && isset( $_GET['subject'] ) && 'recruit' === $_GET['subject'] ) {
	$values['subject'] = '採用について';
}

seizo_page_hero( 'お問い合わせ', 'CONTACT' );
seizo_breadcrumb( array( array( 'label' => 'お問い合わせ' ) ) );
?>

<section class="p-contact">
	<div class="l-container l-container--narrow">

		<ol class="c-steps" aria-label="お問い合わせの手順">
			<li class="c-steps__item <?php echo 'input' === $step ? 'is-current' : 'is-done'; ?>">
				<span class="c-steps__num">1</span>入力
			</li>
			<li class="c-steps__item <?php echo 'confirm' === $step ? 'is-current' : ( 'complete' === $step ? 'is-done' : '' ); ?>">
				<span class="c-steps__num">2</span>確認
			</li>
			<li class="c-steps__item <?php echo 'complete' === $step ? 'is-current' : ''; ?>">
				<span class="c-steps__num">3</span>完了
			</li>
		</ol>

		<div id="form">
		<?php if ( 'complete' === $step ) : ?>

			<div class="p-contact__complete">
				<h2 class="p-contact__complete-title">お問い合わせを受け付けました</h2>
				<p>
					このたびはお問い合わせをいただき、ありがとうございます。<br>
					ご入力いただいたメールアドレス宛に、受付内容の控えをお送りしました。
				</p>
				<p>
					担当者より2営業日以内にご連絡いたします。<br>
					お急ぎの場合は、お手数ですが <a href="tel:<?php echo esc_attr( str_replace( '-', '', $company['tel'] ) ); ?>"><?php echo esc_html( $company['tel'] ); ?></a> までご連絡ください。
				</p>
				<p class="p-contact__complete-back">
					<a class="c-button c-button--ghost" href="<?php echo esc_url( home_url( '/' ) ); ?>">トップページへ戻る</a>
				</p>
			</div>

		<?php elseif ( 'confirm' === $step ) : ?>

			<p class="p-contact__lead">
				ご入力内容をご確認ください。よろしければ「送信する」を押してください。
			</p>

			<?php if ( ! empty( $errors['_form'] ) ) : ?>
				<p class="c-form__error c-form__error--summary" role="alert"><?php echo esc_html( $errors['_form'] ); ?></p>
			<?php endif; ?>

			<form class="c-form c-form--confirm" method="post" action="<?php echo esc_url( get_permalink() ); ?>#form">
				<dl class="c-definition">
					<?php
					foreach ( $fields as $key => $field ) :
						if ( 'privacy' === $key ) {
							continue;
						}

						$value = $values[ $key ] ?? '';
						?>
						<div class="c-definition__row">
							<dt class="c-definition__label"><?php echo esc_html( $field['label'] ); ?></dt>
							<dd class="c-definition__value">
								<?php if ( '' === $value ) : ?>
									<span class="c-definition__empty">（未入力）</span>
								<?php elseif ( 'textarea' === $field['type'] ) : ?>
									<?php echo nl2br( esc_html( $value ) ); ?>
								<?php else : ?>
									<?php echo esc_html( $value ); ?>
								<?php endif; ?>
							</dd>
						</div>
					<?php endforeach; ?>
				</dl>

				<?php
				// 確認画面では値を hidden で持ち回す。
				foreach ( $fields as $key => $field ) :
					?>
					<input type="hidden" name="<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $values[ $key ] ?? '' ); ?>">
				<?php endforeach; ?>

				<?php wp_nonce_field( 'seizo_contact', 'seizo_contact_nonce' ); ?>
				<input type="hidden" name="seizo_ts" value="<?php echo esc_attr( (string) ( time() - 10 ) ); ?>">

				<div class="c-form__actions">
					<button type="submit" name="seizo_action" value="back" class="c-button c-button--ghost">
						修正する
					</button>
					<button type="submit" name="seizo_action" value="send" class="c-button c-button--primary c-button--lg">
						送信する
					</button>
				</div>
			</form>

		<?php else : ?>

			<p class="p-contact__lead">
				製品・加工に関するご相談、お見積りのご依頼を承ります。<br>
				<span class="p-contact__required-note">「必須」の項目は必ずご入力ください。</span>
			</p>

			<?php if ( ! empty( $errors['_form'] ) ) : ?>
				<p class="c-form__error c-form__error--summary" role="alert"><?php echo esc_html( $errors['_form'] ); ?></p>
			<?php elseif ( $errors ) : ?>
				<p class="c-form__error c-form__error--summary" role="alert">
					ご入力内容に誤りがあります。以下の項目をご確認ください。
				</p>
			<?php endif; ?>

			<form class="c-form" method="post" action="<?php echo esc_url( get_permalink() ); ?>#form" novalidate>
				<?php
				foreach ( $fields as $key => $field ) {
					seizo_form_field( $key, $field, $values, $errors );
				}
				?>

				<?php wp_nonce_field( 'seizo_contact', 'seizo_contact_nonce' ); ?>
				<input type="hidden" name="seizo_ts" value="<?php echo esc_attr( (string) time() ); ?>">

				<?php // ボット対策。CSS で隠し、スクリーンリーダーからも外す。 ?>
				<div class="c-form__hp" aria-hidden="true">
					<label for="seizo-hp">この欄は入力しないでください</label>
					<input type="text" id="seizo-hp" name="seizo_hp" value="" tabindex="-1" autocomplete="off">
				</div>

				<div class="c-form__actions">
					<button type="submit" name="seizo_action" value="confirm" class="c-button c-button--primary c-button--lg">
						入力内容を確認する
					</button>
				</div>
			</form>

			<div class="p-contact__tel">
				<h2 class="p-contact__tel-title">お電話でのお問い合わせ</h2>
				<p class="p-contact__tel-num">
					<a href="tel:<?php echo esc_attr( str_replace( '-', '', $company['tel'] ) ); ?>">
						<?php echo esc_html( $company['tel'] ); ?>
					</a>
				</p>
				<p class="p-contact__tel-hours"><?php echo esc_html( $company['hours'] ); ?></p>
			</div>

		<?php endif; ?>
		</div>
	</div>
</section>

<?php
get_footer();
