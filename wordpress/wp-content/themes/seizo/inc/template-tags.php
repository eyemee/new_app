<?php
/**
 * テンプレートから呼ぶ表示用ヘルパー。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * 下層ページ共通の見出し（ページヘッダー）。
 *
 * @param string $title 和文見出し。
 * @param string $en    英文見出し。デザイン上、下層は和英併記。
 */
function seizo_page_hero( $title, $en = '' ) {
	?>
	<div class="c-page-hero">
		<div class="l-container">
			<h1 class="c-page-hero__title"><?php echo esc_html( $title ); ?></h1>
			<?php if ( $en ) : ?>
				<p class="c-page-hero__en"><?php echo esc_html( $en ); ?></p>
			<?php endif; ?>
		</div>
	</div>
	<?php
}

/**
 * パンくず。
 *
 * @param array<int,array{label:string,url?:string}> $trail 中間階層。最後の要素は現在地。
 */
function seizo_breadcrumb( array $trail ) {
	?>
	<nav class="c-breadcrumb" aria-label="パンくずリスト">
		<div class="l-container">
			<ol class="c-breadcrumb__list">
				<li class="c-breadcrumb__item">
					<a href="<?php echo esc_url( home_url( '/' ) ); ?>">ホーム</a>
				</li>
				<?php foreach ( $trail as $index => $crumb ) : ?>
					<li class="c-breadcrumb__item">
						<?php if ( ! empty( $crumb['url'] ) && $index < count( $trail ) - 1 ) : ?>
							<a href="<?php echo esc_url( $crumb['url'] ); ?>"><?php echo esc_html( $crumb['label'] ); ?></a>
						<?php else : ?>
							<span aria-current="page"><?php echo esc_html( $crumb['label'] ); ?></span>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ol>
		</div>
	</nav>
	<?php
}

/**
 * ページ送り。
 */
function seizo_pagination() {
	$links = paginate_links(
		array(
			'type'      => 'array',
			'mid_size'  => 2,
			'prev_text' => '前へ',
			'next_text' => '次へ',
		)
	);

	if ( empty( $links ) ) {
		return;
	}
	?>
	<nav class="c-pagination" aria-label="ページ送り">
		<ul class="c-pagination__list">
			<?php foreach ( $links as $link ) : ?>
				<li class="c-pagination__item"><?php echo wp_kses_post( $link ); ?></li>
			<?php endforeach; ?>
		</ul>
	</nav>
	<?php
}

/**
 * フォーム項目の入力欄を描画する。
 *
 * @param string               $key    項目キー。
 * @param array<string,mixed>  $field  項目定義。
 * @param array<string,string> $values 現在値。
 * @param array<string,string> $errors エラー。
 */
function seizo_form_field( $key, array $field, array $values, array $errors ) {
	$value     = $values[ $key ] ?? '';
	$error     = $errors[ $key ] ?? '';
	$id        = 'field-' . $key;
	$describe  = $error ? $id . '-error' : '';
	$autocomp  = $field['autocomplete'] ?? '';
	$row_class = 'c-form__row' . ( $error ? ' is-error' : '' );
	?>
	<div class="<?php echo esc_attr( $row_class ); ?>">
		<div class="c-form__label">
			<label for="<?php echo esc_attr( $id ); ?>"><?php echo esc_html( $field['label'] ); ?></label>
			<?php if ( ! empty( $field['required'] ) ) : ?>
				<span class="c-form__required">必須</span>
			<?php endif; ?>
		</div>

		<div class="c-form__control">
			<?php if ( 'textarea' === $field['type'] ) : ?>
				<textarea
					id="<?php echo esc_attr( $id ); ?>"
					name="<?php echo esc_attr( $key ); ?>"
					rows="8"
					<?php echo $describe ? 'aria-describedby="' . esc_attr( $describe ) . '"' : ''; ?>
					<?php echo ! empty( $field['required'] ) ? 'required' : ''; ?>
				><?php echo esc_textarea( $value ); ?></textarea>

			<?php elseif ( 'select' === $field['type'] ) : ?>
				<select
					id="<?php echo esc_attr( $id ); ?>"
					name="<?php echo esc_attr( $key ); ?>"
					<?php echo $describe ? 'aria-describedby="' . esc_attr( $describe ) . '"' : ''; ?>
					<?php echo ! empty( $field['required'] ) ? 'required' : ''; ?>
				>
					<option value="">選択してください</option>
					<?php foreach ( $field['options'] as $option ) : ?>
						<option value="<?php echo esc_attr( $option ); ?>" <?php selected( $value, $option ); ?>>
							<?php echo esc_html( $option ); ?>
						</option>
					<?php endforeach; ?>
				</select>

			<?php elseif ( 'checkbox' === $field['type'] ) : ?>
				<label class="c-form__check">
					<input
						type="checkbox"
						id="<?php echo esc_attr( $id ); ?>"
						name="<?php echo esc_attr( $key ); ?>"
						value="1"
						<?php checked( $value, '1' ); ?>
						<?php echo $describe ? 'aria-describedby="' . esc_attr( $describe ) . '"' : ''; ?>
					>
					<span>
						<a href="<?php echo esc_url( home_url( '/privacy/' ) ); ?>" target="_blank" rel="noopener">個人情報の取り扱い</a>
						に同意します
					</span>
				</label>

			<?php else : ?>
				<input
					type="<?php echo esc_attr( $field['type'] ); ?>"
					id="<?php echo esc_attr( $id ); ?>"
					name="<?php echo esc_attr( $key ); ?>"
					value="<?php echo esc_attr( $value ); ?>"
					<?php echo $autocomp ? 'autocomplete="' . esc_attr( $autocomp ) . '"' : ''; ?>
					<?php echo isset( $field['max'] ) ? 'maxlength="' . esc_attr( (string) $field['max'] ) . '"' : ''; ?>
					<?php echo $describe ? 'aria-describedby="' . esc_attr( $describe ) . '"' : ''; ?>
					<?php echo ! empty( $field['required'] ) ? 'required' : ''; ?>
				>
			<?php endif; ?>

			<?php if ( 'zip' === $key ) : ?>
				<p class="c-form__note">ハイフンあり・なしどちらでも入力できます。入力すると住所が自動で補完されます。</p>
			<?php endif; ?>

			<?php if ( $error ) : ?>
				<p class="c-form__error" id="<?php echo esc_attr( $describe ); ?>" role="alert">
					<?php echo esc_html( $error ); ?>
				</p>
			<?php endif; ?>
		</div>
	</div>
	<?php
}

/**
 * 外部サイトへ出るリンクであることを示すアイコン付きリンク。
 * 製品一覧が現行サイトへ飛ぶため、遷移先が変わることを明示する。
 *
 * @param string $url   リンク先。
 * @param string $label 表示文字列。
 * @param string $class 追加クラス。
 */
function seizo_external_link( $url, $label, $class = '' ) {
	?>
	<a
		class="c-external <?php echo esc_attr( $class ); ?>"
		href="<?php echo esc_url( $url ); ?>"
		target="_blank"
		rel="noopener"
	>
		<span><?php echo esc_html( $label ); ?></span>
		<span class="c-external__icon" aria-hidden="true"></span>
		<span class="u-visually-hidden">（別サイトが新しいタブで開きます）</span>
	</a>
	<?php
}

/**
 * メニュー未設定時のナビ。テーマ有効化直後や、メニューを消してしまった場合でも
 * サイトの導線が消えないようにする。
 */
function seizo_nav_fallback() {
	$items = array(
		'/company/'  => '会社概要',
		'/business/' => '事業・製品',
		'/news/'     => 'お知らせ',
		'/quality/'  => '品質・技術',
		'/recruit/'  => '採用情報',
		'/contact/'  => 'お問い合わせ',
	);
	?>
	<ul class="l-nav__list">
		<?php foreach ( $items as $path => $label ) : ?>
			<li class="l-nav__item">
				<a href="<?php echo esc_url( home_url( $path ) ); ?>"><?php echo esc_html( $label ); ?></a>
			</li>
		<?php endforeach; ?>
	</ul>
	<?php
}
