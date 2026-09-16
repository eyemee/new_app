<?php
/**
 * テーマのロジック検証。
 *
 *   php tests/run.php
 *
 * WordPress を起動せず、tests/bootstrap.php のスタブ上で
 * 入力検証と郵便番号まわりの挙動を確認する。
 */

require_once __DIR__ . '/bootstrap.php';

$passed = 0;
$failed = 0;

/**
 * @param string $name     テスト名。
 * @param mixed  $expected 期待値。
 * @param mixed  $actual   実際の値。
 */
function check( $name, $expected, $actual ) {
	global $passed, $failed;

	if ( $expected === $actual ) {
		$passed++;
		printf( "  ok   %s\n", $name );
		return;
	}

	$failed++;
	printf(
		"  FAIL %s\n       expected: %s\n       actual:   %s\n",
		$name,
		var_export( $expected, true ),
		var_export( $actual, true )
	);
}

/**
 * 有効な入力一式。各テストで必要な項目だけ差し替えて使う。
 *
 * @return array<string,string>
 */
function valid_input() {
	return array(
		'company'    => '株式会社テスト',
		'department' => '生産技術部',
		'name'       => '山田 太郎',
		'kana'       => 'ヤマダ タロウ',
		'email'      => 'yamada@example.co.jp',
		'tel'        => '052-123-4567',
		'zip'        => '460-0008',
		'prefecture' => '愛知県',
		'city'       => '名古屋市中区栄',
		'address'    => '1-1-1',
		'subject'    => '製品について',
		'message'    => 'テスト送信です。',
		'privacy'    => '1',
	);
}

echo "\n入力検証\n";
seizo_test_reset();

check( '正しい入力はエラーなし', array(), seizo_validate_contact( valid_input() ) );

$input = valid_input();
$input['company'] = '';
check(
	'必須項目（会社名）が空ならエラー',
	'会社名を入力してください。',
	seizo_validate_contact( $input )['company'] ?? null
);

$input = valid_input();
$input['department'] = '';
check( '任意項目（部署名）は空でも通る', array(), seizo_validate_contact( $input ) );

$input = valid_input();
$input['email'] = 'yamada.example.co.jp';
check(
	'メール形式の誤りを検出',
	'メールアドレスの形式が正しくありません。',
	seizo_validate_contact( $input )['email'] ?? null
);

$input = valid_input();
$input['kana'] = 'Yamada Taro';
check(
	'フリガナに英字が入っていたら弾く',
	'フリガナはかな文字で入力してください。',
	seizo_validate_contact( $input )['kana'] ?? null
);

$input = valid_input();
$input['kana'] = 'やまだ たろう';
check( 'フリガナはひらがなでも通る', array(), seizo_validate_contact( $input ) );

$input = valid_input();
$input['tel'] = '05212345678';
check( '電話番号はハイフンなしでも通る', array(), seizo_validate_contact( $input ) );

$input = valid_input();
$input['tel'] = '電話ください';
check(
	'電話番号に文字列は通さない',
	'電話番号は数字とハイフンで入力してください。',
	seizo_validate_contact( $input )['tel'] ?? null
);

$input = valid_input();
$input['zip'] = '4600008';
check( '郵便番号はハイフンなしでも通る', array(), seizo_validate_contact( $input ) );

$input = valid_input();
$input['zip'] = '460-00';
check(
	'桁数の足りない郵便番号を検出',
	'郵便番号は7桁の数字で入力してください。（例: 460-0008）',
	seizo_validate_contact( $input )['zip'] ?? null
);

$input = valid_input();
$input['privacy'] = '';
check(
	'個人情報の同意なしは送信不可',
	'個人情報の取り扱いについてご同意ください。',
	seizo_validate_contact( $input )['privacy'] ?? null
);

$input = valid_input();
$input['subject'] = '選択肢にない値';
check(
	'選択肢にない種別は弾く（改ざん対策）',
	'お問い合わせ種別を選択してください。',
	seizo_validate_contact( $input )['subject'] ?? null
);

$input = valid_input();
$input['message'] = str_repeat( 'あ', 2001 );
check(
	'本文の文字数上限を超えたら弾く',
	'お問い合わせ内容は2000文字以内で入力してください。',
	seizo_validate_contact( $input )['message'] ?? null
);

$input = valid_input();
$input['message'] = str_repeat( 'あ', 2000 );
check( '上限ちょうどは通る', array(), seizo_validate_contact( $input ) );

echo "\nボット対策\n";
seizo_test_reset();

$_POST['seizo_hp'] = 'https://spam.example.com';
check(
	'ハニーポットが埋まっていたら弾く',
	'送信できませんでした。',
	seizo_validate_contact( valid_input() )['_form'] ?? null
);

seizo_test_reset();
$_POST['seizo_ts'] = time();
check(
	'表示直後の即時送信は弾く',
	'送信できませんでした。お手数ですが、もう一度お試しください。',
	seizo_validate_contact( valid_input() )['_form'] ?? null
);

seizo_test_reset();
$_POST['seizo_ts'] = time() - 30;
check( '通常の送信間隔なら通る', array(), seizo_validate_contact( valid_input() ) );

echo "\n入力値の取り込み\n";
seizo_test_reset();

$_POST = array(
	'name'    => "  山田 太郎\r\n  ",
	'message' => "1行目\n2行目",
	'privacy' => '1',
);
$collected = seizo_collect_contact_values();

check( '前後の空白と改行を落とす', '山田 太郎', $collected['name'] );
check( '本文の改行は保持する', "1行目\n2行目", $collected['message'] );
check( 'チェックボックスは 1 に正規化', '1', $collected['privacy'] );
check( '未送信の項目は空文字', '', $collected['tel'] );

echo "\n送信回数の制限\n";
seizo_test_reset();

$allowed = 0;
for ( $i = 0; $i < 8; $i++ ) {
	if ( seizo_contact_within_rate_limit() ) {
		$allowed++;
	}
}
check( '同一 IP からの送信は5回まで', 5, $allowed );

echo "\nメール送信\n";
seizo_test_reset();

$sent = seizo_send_contact_mail( valid_input() );
check( '送信が成功する', true, $sent );
check( '通知と自動返信の2通が出る', 2, count( $GLOBALS['seizo_test_mail'] ) );
check( '通知の宛先は設定した受信アドレス', 'test@example.co.jp', $GLOBALS['seizo_test_mail'][0]['to'] );
check( '自動返信の宛先は送信者', 'yamada@example.co.jp', $GLOBALS['seizo_test_mail'][1]['to'] );
check(
	'本文に問い合わせ内容が含まれる',
	true,
	str_contains( $GLOBALS['seizo_test_mail'][0]['body'], 'テスト送信です。' )
);

seizo_test_reset();
$injected         = valid_input();
$injected['name'] = "山田\r\nBcc: attacker@example.com";
seizo_send_contact_mail( $injected );
$headers = implode( ' ', $GLOBALS['seizo_test_mail'][0]['headers'] );
check(
	'Reply-To に改行を混ぜられない（ヘッダインジェクション対策）',
	false,
	str_contains( $headers, "\n" ) || str_contains( $headers, "\r" )
);

echo "\n郵便番号の検索\n";
seizo_test_reset();

$GLOBALS['seizo_test_remote'] = array(
	'response' => array( 'code' => 200 ),
	'body'     => json_encode(
		array(
			'status'  => 200,
			'results' => array(
				array(
					'address1' => '愛知県',
					'address2' => '名古屋市中区',
					'address3' => '栄',
					'zipcode'  => '4600008',
				),
			),
		)
	),
);

$address = seizo_lookup_zipcode( '4600008' );
check( '都道府県を取得', '愛知県', $address['prefecture'] ?? null );
check( '市区町村を取得', '名古屋市中区', $address['city'] ?? null );
check( '町名を取得', '栄', $address['town'] ?? null );
check( '連結した住所を返す', '愛知県名古屋市中区栄', $address['full'] ?? null );

// 2回目は外部へ出ずキャッシュから返ること。
$GLOBALS['seizo_test_remote'] = null;
$cached = seizo_lookup_zipcode( '4600008' );
check( '2回目はキャッシュから返す', '愛知県名古屋市中区栄', $cached['full'] ?? null );

seizo_test_reset();
$GLOBALS['seizo_test_remote'] = array(
	'response' => array( 'code' => 200 ),
	'body'     => json_encode( array( 'status' => 200, 'results' => null ) ),
);
check( '該当なしは null を返す', null, seizo_lookup_zipcode( '9999999' ) );

seizo_test_reset();
$GLOBALS['seizo_test_remote'] = new WP_Error( 'http_request_failed', 'timeout' );
check( '外部 API の障害時も落ちずに null', null, seizo_lookup_zipcode( '4600008' ) );

seizo_test_reset();
seizo_test_add_filter(
	'seizo_zipcode_provider',
	static function ( $address, $zipcode ) {
		return array(
			'prefecture' => '愛知県',
			'city'       => '名古屋市中村区',
			'town'       => '名駅',
			'full'       => '愛知県名古屋市中村区名駅',
		);
	}
);
$GLOBALS['seizo_test_remote'] = null; // 外部へは出ないはず。
check(
	'フィルタで参照先を差し替えられる',
	'愛知県名古屋市中村区名駅',
	seizo_lookup_zipcode( '4500002' )['full'] ?? null
);

printf( "\n%d passed, %d failed\n\n", $passed, $failed );

exit( $failed > 0 ? 1 : 0 );
