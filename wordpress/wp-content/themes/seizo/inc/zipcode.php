<?php
/**
 * 郵便番号 → 住所の自動入力。
 *
 * ブラウザから外部 API を直接叩かず、WordPress 側の REST エンドポイントを
 * 経由させている。理由:
 *  - 外部 API の CORS 設定に依存しない（JSONP 回避）。
 *  - 結果をサーバー側にキャッシュでき、同じ番号で外部へ出ていかない。
 *  - 納品後に参照先を差し替える場合、JS を触らずサーバー側だけで完結する。
 *
 * 参照先は seizo_zipcode_provider フィルタで差し替え可能。クライアントの
 * サーバーが外向き通信を許可していない場合は、日本郵便の KEN_ALL から作った
 * ローカルテーブルを返す実装に差し替えれば、フロントはそのまま動く。
 *
 * @package Seizo
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const SEIZO_ZIP_CACHE_PREFIX = 'seizo_zip_';
const SEIZO_ZIP_CACHE_TTL    = MONTH_IN_SECONDS;

/**
 * REST ルートの登録。
 */
function seizo_register_zipcode_route() {
	register_rest_route(
		'seizo/v1',
		'/zipcode/(?P<zipcode>[0-9]{7})',
		array(
			'methods'             => WP_REST_Server::READABLE,
			'callback'            => 'seizo_zipcode_response',
			'permission_callback' => '__return_true',
			'args'                => array(
				'zipcode' => array(
					'required'          => true,
					'validate_callback' => static function ( $value ) {
						return (bool) preg_match( '/\A[0-9]{7}\z/', (string) $value );
					},
				),
			),
		)
	);
}
add_action( 'rest_api_init', 'seizo_register_zipcode_route' );

/**
 * エンドポイントの応答。
 *
 * @param WP_REST_Request $request リクエスト。
 * @return WP_REST_Response
 */
function seizo_zipcode_response( WP_REST_Request $request ) {
	$zipcode = preg_replace( '/[^0-9]/', '', (string) $request->get_param( 'zipcode' ) );
	$address = seizo_lookup_zipcode( $zipcode );

	if ( null === $address ) {
		return new WP_REST_Response(
			array(
				'found'   => false,
				'message' => '該当する住所が見つかりませんでした。',
			),
			200
		);
	}

	return new WP_REST_Response(
		array(
			'found'   => true,
			'zipcode' => $zipcode,
			'address' => $address,
		),
		200
	);
}

/**
 * 郵便番号から住所を引く。キャッシュ → プロバイダの順。
 *
 * 見つからなかった場合も「見つからない」という結果をキャッシュする。
 * 打ち間違いの連打でそのつど外部に出ていくのを防ぐため。
 *
 * @param string $zipcode ハイフンなし7桁。
 * @return array{prefecture:string,city:string,town:string,full:string}|null
 */
function seizo_lookup_zipcode( $zipcode ) {
	$cache_key = SEIZO_ZIP_CACHE_PREFIX . $zipcode;
	$cached    = get_transient( $cache_key );

	if ( false !== $cached ) {
		return is_array( $cached ) ? $cached : null;
	}

	/**
	 * 住所の取得方法を差し替えるためのフィルタ。
	 *
	 * null 以外を返すとその値が採用され、既定の外部問い合わせは行われない。
	 *
	 * @param array|null $address 住所。
	 * @param string     $zipcode 郵便番号。
	 */
	$address = apply_filters( 'seizo_zipcode_provider', null, $zipcode );

	if ( null === $address ) {
		$address = seizo_fetch_zipcode_remote( $zipcode );
	}

	// 失敗をキャッシュするときは短め。API 側の一時障害を長く引きずらないため。
	set_transient(
		$cache_key,
		null === $address ? 'none' : $address,
		null === $address ? HOUR_IN_SECONDS : SEIZO_ZIP_CACHE_TTL
	);

	return $address;
}

/**
 * 既定のプロバイダ（zipcloud）へ問い合わせる。
 *
 * @param string $zipcode 郵便番号。
 * @return array{prefecture:string,city:string,town:string,full:string}|null
 */
function seizo_fetch_zipcode_remote( $zipcode ) {
	$endpoint = add_query_arg(
		'zipcode',
		$zipcode,
		'https://zipcloud.ibsnet.co.jp/api/search'
	);

	$response = wp_remote_get(
		$endpoint,
		array(
			'timeout' => 5,
			'headers' => array( 'Accept' => 'application/json' ),
		)
	);

	if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
		return null;
	}

	$body = json_decode( wp_remote_retrieve_body( $response ), true );

	if ( ! is_array( $body ) || empty( $body['results'][0] ) ) {
		return null;
	}

	$result = $body['results'][0];

	$prefecture = isset( $result['address1'] ) ? (string) $result['address1'] : '';
	$city       = isset( $result['address2'] ) ? (string) $result['address2'] : '';
	$town       = isset( $result['address3'] ) ? (string) $result['address3'] : '';

	if ( '' === $prefecture ) {
		return null;
	}

	return array(
		'prefecture' => $prefecture,
		'city'       => $city,
		'town'       => $town,
		'full'       => $prefecture . $city . $town,
	);
}
