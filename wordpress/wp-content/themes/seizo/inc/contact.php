<?php
/**
 * お問い合わせフォーム。
 *
 * プラグインを使わずテーマ内で完結させている（既製テーマ・既製プラグイン不可の要件、
 * および納品先サーバーでの追加インストールを前提にしないため）。
 *
 * 画面遷移は日本のコーポレートサイトの慣習に合わせて 入力 → 確認 → 完了 の3段。
 * 送信後は PRG（Post/Redirect/Get）でリダイレクトし、リロードによる二重送信を防ぐ。
 * 処理は template_redirect で走らせるので、ヘッダー送出前にリダイレクトできる。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * フォーム項目の定義。
 *
 * バリデーション・確認画面・メール本文がすべてこの配列を回すので、
 * 項目の追加はここ1か所で済む。
 *
 * @return array<string,array<string,mixed>>
 */
function seizo_contact_fields() {
	return array(
		'company'    => array(
			'label'    => '会社名',
			'type'     => 'text',
			'required' => true,
			'max'      => 100,
			'autocomplete' => 'organization',
		),
		'department' => array(
			'label'    => '部署名',
			'type'     => 'text',
			'required' => false,
			'max'      => 100,
			'autocomplete' => 'organization-title',
		),
		'name'       => array(
			'label'    => 'お名前',
			'type'     => 'text',
			'required' => true,
			'max'      => 60,
			'autocomplete' => 'name',
		),
		'kana'       => array(
			'label'    => 'フリガナ',
			'type'     => 'text',
			'required' => true,
			'max'      => 60,
			'rule'     => 'kana',
		),
		'email'      => array(
			'label'    => 'メールアドレス',
			'type'     => 'email',
			'required' => true,
			'max'      => 120,
			'rule'     => 'email',
			'autocomplete' => 'email',
		),
		'tel'        => array(
			'label'    => '電話番号',
			'type'     => 'tel',
			'required' => true,
			'max'      => 20,
			'rule'     => 'tel',
			'autocomplete' => 'tel',
		),
		'zip'        => array(
			'label'    => '郵便番号',
			'type'     => 'text',
			'required' => false,
			'max'      => 8,
			'rule'     => 'zip',
			'autocomplete' => 'postal-code',
		),
		'prefecture' => array(
			'label'    => '都道府県',
			'type'     => 'text',
			'required' => false,
			'max'      => 10,
			'autocomplete' => 'address-level1',
		),
		'city'       => array(
			'label'    => '市区町村',
			'type'     => 'text',
			'required' => false,
			'max'      => 100,
			'autocomplete' => 'address-level2',
		),
		'address'    => array(
			'label'    => '番地・建物名',
			'type'     => 'text',
			'required' => false,
			'max'      => 150,
			'autocomplete' => 'address-line1',
		),
		'subject'    => array(
			'label'    => 'お問い合わせ種別',
			'type'     => 'select',
			'required' => true,
			'options'  => array(
				'製品について',
				'お見積り・ご注文について',
				'技術・加工のご相談',
				'採用について',
				'取材・広報について',
				'その他',
			),
		),
		'message'    => array(
			'label'    => 'お問い合わせ内容',
			'type'     => 'textarea',
			'required' => true,
			'max'      => 2000,
		),
		'privacy'    => array(
			'label'    => '個人情報の取り扱い',
			'type'     => 'checkbox',
			'required' => true,
		),
	);
}

/**
 * フォームの現在の状態を返す。テンプレートから参照する。
 *
 * 状態は参照で持ち回るため、実体は seizo_contact_state_ref() 側にある。
 *
 * @return array{step:string,values:array<string,string>,errors:array<string,string>}
 */
function seizo_contact_state() {
	return seizo_contact_state_ref();
}

/**
 * 状態の実体への参照を返す。書き換えるのは seizo_handle_contact() のみ。
 *
 * @return array
 */
function &seizo_contact_state_ref() {
	static $state = array(
		'step'   => 'input',
		'values' => array(),
		'errors' => array(),
	);

	return $state;
}

/**
 * POST を処理する。
 */
function seizo_handle_contact() {
	if ( ! is_page( 'contact' ) ) {
		return;
	}

	$state = &seizo_contact_state_ref();

	// 送信完了後のリダイレクト着地点。
	if ( isset( $_GET['sent'] ) && '1' === $_GET['sent'] ) {
		$state['step'] = 'complete';
		return;
	}

	if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
		return;
	}

	if ( ! isset( $_POST['seizo_contact_nonce'] ) ||
		! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['seizo_contact_nonce'] ) ), 'seizo_contact' ) ) {
		$state['errors']['_form'] = '送信の有効期限が切れました。お手数ですが、もう一度ご入力ください。';
		return;
	}

	$values = seizo_collect_contact_values();
	$action = isset( $_POST['seizo_action'] ) ? sanitize_key( wp_unslash( $_POST['seizo_action'] ) ) : 'confirm';

	$state['values'] = $values;

	// 「修正する」で入力画面へ戻る。この時点では検証しない。
	if ( 'back' === $action ) {
		$state['step'] = 'input';
		return;
	}

	$errors = seizo_validate_contact( $values );

	if ( $errors ) {
		$state['step']   = 'input';
		$state['errors'] = $errors;
		return;
	}

	if ( 'confirm' === $action ) {
		$state['step'] = 'confirm';
		return;
	}

	if ( 'send' === $action ) {
		if ( ! seizo_contact_within_rate_limit() ) {
			$state['step']            = 'input';
			$state['errors']['_form'] = '送信が続けて行われました。しばらく時間をおいてからお試しください。';
			return;
		}

		if ( seizo_send_contact_mail( $values ) ) {
			wp_safe_redirect( add_query_arg( 'sent', '1', get_permalink() ) . '#form' );
			exit;
		}

		$state['step']            = 'confirm';
		$state['errors']['_form'] = '送信処理に失敗しました。お手数ですが、お電話にてご連絡ください。';
	}
}
add_action( 'template_redirect', 'seizo_handle_contact' );

/**
 * POST 値を項目定義にそって取り出す。
 *
 * @return array<string,string>
 */
function seizo_collect_contact_values() {
	$values = array();

	foreach ( seizo_contact_fields() as $key => $field ) {
		$raw = isset( $_POST[ $key ] ) ? wp_unslash( $_POST[ $key ] ) : '';

		if ( 'textarea' === $field['type'] ) {
			$values[ $key ] = sanitize_textarea_field( $raw );
		} elseif ( 'email' === $field['type'] ) {
			$values[ $key ] = sanitize_email( $raw );
		} elseif ( 'checkbox' === $field['type'] ) {
			$values[ $key ] = '' !== $raw ? '1' : '';
		} else {
			$values[ $key ] = sanitize_text_field( $raw );
		}
	}

	return $values;
}

/**
 * 入力値を検証する。
 *
 * @param array<string,string> $values 入力値。
 * @return array<string,string> 項目名 => エラーメッセージ。
 */
function seizo_validate_contact( array $values ) {
	$errors = array();

	// ボット対策1: 人間には見えない項目。埋まっていたら弾く。
	if ( ! empty( $_POST['seizo_hp'] ) ) {
		$errors['_form'] = '送信できませんでした。';
		return $errors;
	}

	// ボット対策2: フォーム表示から送信までが短すぎる場合。
	$rendered = isset( $_POST['seizo_ts'] ) ? (int) $_POST['seizo_ts'] : 0;
	if ( $rendered > 0 && ( time() - $rendered ) < 3 ) {
		$errors['_form'] = '送信できませんでした。お手数ですが、もう一度お試しください。';
		return $errors;
	}

	foreach ( seizo_contact_fields() as $key => $field ) {
		$value = $values[ $key ] ?? '';

		if ( ! empty( $field['required'] ) && '' === $value ) {
			$errors[ $key ] = 'checkbox' === $field['type']
				? '個人情報の取り扱いについてご同意ください。'
				: $field['label'] . 'を入力してください。';
			continue;
		}

		if ( '' === $value ) {
			continue;
		}

		if ( isset( $field['max'] ) && mb_strlen( $value ) > $field['max'] ) {
			$errors[ $key ] = $field['label'] . 'は' . $field['max'] . '文字以内で入力してください。';
			continue;
		}

		if ( 'select' === $field['type'] && ! in_array( $value, $field['options'], true ) ) {
			$errors[ $key ] = $field['label'] . 'を選択してください。';
			continue;
		}

		switch ( $field['rule'] ?? '' ) {
			case 'email':
				if ( ! is_email( $value ) ) {
					$errors[ $key ] = 'メールアドレスの形式が正しくありません。';
				}
				break;

			case 'tel':
				if ( ! preg_match( '/\A[0-9０-９\-－\(\)\s]{9,20}\z/u', $value ) ) {
					$errors[ $key ] = '電話番号は数字とハイフンで入力してください。';
				}
				break;

			case 'zip':
				if ( ! preg_match( '/\A[0-9]{3}-?[0-9]{4}\z/', $value ) ) {
					$errors[ $key ] = '郵便番号は7桁の数字で入力してください。（例: 460-0008）';
				}
				break;

			case 'kana':
				// 全角カナ・ひらがな・長音・スペースのみ許可。
				if ( ! preg_match( '/\A[ぁ-んァ-ヶーー\s　]+\z/u', $value ) ) {
					$errors[ $key ] = 'フリガナはかな文字で入力してください。';
				}
				break;
		}
	}

	return $errors;
}

/**
 * 同一 IP からの連続送信を抑える。
 *
 * @return bool 送信してよければ true。
 */
function seizo_contact_within_rate_limit() {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

	if ( '' === $ip ) {
		return true;
	}

	$key   = 'seizo_contact_' . md5( $ip );
	$count = (int) get_transient( $key );

	if ( $count >= 5 ) {
		return false;
	}

	set_transient( $key, $count + 1, HOUR_IN_SECONDS );

	return true;
}

/**
 * 管理者への通知と、送信者への自動返信。
 *
 * @param array<string,string> $values 入力値。
 * @return bool 管理者宛が送れたか。
 */
function seizo_send_contact_mail( array $values ) {
	$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
	$subject = sprintf( '[%s] お問い合わせ（%s）', $site, $values['subject'] );

	// 件名・ヘッダーに改行が混ざらないようにする。
	$subject = str_replace( array( "\r", "\n" ), '', $subject );

	$body    = seizo_contact_mail_body( $values );
	$headers = array(
		'Content-Type: text/plain; charset=UTF-8',
		sprintf( 'Reply-To: %s <%s>', str_replace( array( "\r", "\n" ), '', $values['name'] ), $values['email'] ),
	);

	$sent = wp_mail( SEIZO_CONTACT_TO, $subject, $body, $headers );

	if ( $sent ) {
		seizo_send_contact_autoreply( $values, $site );
	}

	return (bool) $sent;
}

/**
 * 通知メールの本文。
 *
 * @param array<string,string> $values 入力値。
 * @return string
 */
function seizo_contact_mail_body( array $values ) {
	$lines = array(
		'ウェブサイトのお問い合わせフォームから送信がありました。',
		'',
		str_repeat( '-', 48 ),
	);

	foreach ( seizo_contact_fields() as $key => $field ) {
		if ( 'privacy' === $key ) {
			continue;
		}

		$value = $values[ $key ] ?? '';
		$lines[] = $field['label'] . ': ' . ( '' === $value ? '（未入力）' : $value );
	}

	$lines[] = str_repeat( '-', 48 );
	$lines[] = '';
	$lines[] = '送信日時: ' . wp_date( 'Y年n月j日 H:i' );
	$lines[] = '送信元 IP: ' . ( isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '不明' );

	return implode( "\n", $lines );
}

/**
 * 送信者への自動返信。
 *
 * @param array<string,string> $values 入力値。
 * @param string               $site   サイト名。
 */
function seizo_send_contact_autoreply( array $values, $site ) {
	$subject = sprintf( '【%s】お問い合わせを受け付けました', $site );
	$subject = str_replace( array( "\r", "\n" ), '', $subject );

	$body = implode(
		"\n",
		array(
			$values['company'] . "\n" . $values['name'] . ' 様',
			'',
			'このたびはお問い合わせをいただき、誠にありがとうございます。',
			'以下の内容で受け付けいたしました。担当者より改めてご連絡いたします。',
			'',
			str_repeat( '-', 48 ),
			'お問い合わせ種別: ' . $values['subject'],
			'',
			$values['message'],
			str_repeat( '-', 48 ),
			'',
			'※このメールは自動送信です。ご返信いただいてもお答えできません。',
			'',
			$site,
		)
	);

	wp_mail(
		$values['email'],
		$subject,
		$body,
		array( 'Content-Type: text/plain; charset=UTF-8' )
	);
}
