/**
 * 郵便番号 → 住所の自動入力。
 *
 * 入力のたびに問い合わせると無駄な通信が増えるので、7桁そろった時点で
 * 1回だけ叩く。連続入力に備えて直前のリクエストは中断する。
 *
 * 都道府県・市区町村は自動で埋め、番地は必ず人が入れる項目なので
 * 触らずフォーカスだけ移す。すでに人が手で書いた住所を消さないよう、
 * 上書きするのは「自動入力で入れた値のまま」か「空」のときだけ。
 */
(function () {
	'use strict';

	var config = window.seizoContact;

	if (!config || !config.zipEndpoint) {
		return;
	}

	var zipField = document.getElementById('field-zip');
	var prefField = document.getElementById('field-prefecture');
	var cityField = document.getElementById('field-city');
	var addressField = document.getElementById('field-address');

	if (!zipField || !prefField || !cityField) {
		return;
	}

	var controller = null;
	var lastLookup = '';
	// 自動入力で入れた値を覚えておき、人の入力と区別する。
	var filled = { prefecture: '', city: '' };

	/**
	 * 全角数字・ハイフンを半角に寄せ、数字だけを取り出す。
	 */
	function normalize(value) {
		return value
			.replace(/[０-９]/g, function (char) {
				return String.fromCharCode(char.charCodeAt(0) - 0xfee0);
			})
			.replace(/[^0-9]/g, '');
	}

	function canOverwrite(field, key) {
		return field.value === '' || field.value === filled[key];
	}

	function apply(field, key, value) {
		if (!canOverwrite(field, key)) {
			return;
		}

		field.value = value;
		filled[key] = value;

		field.classList.remove('is-autofilled');
		// クラスを付け直してアニメーションを再生させる。
		void field.offsetWidth;
		field.classList.add('is-autofilled');
	}

	function lookup(zipcode) {
		if (zipcode === lastLookup) {
			return;
		}

		lastLookup = zipcode;

		if (controller) {
			controller.abort();
		}

		controller = typeof AbortController === 'function' ? new AbortController() : null;

		var options = { headers: { Accept: 'application/json' } };
		if (controller) {
			options.signal = controller.signal;
		}

		fetch(config.zipEndpoint + '/' + zipcode, options)
			.then(function (response) {
				return response.ok ? response.json() : null;
			})
			.then(function (data) {
				if (!data || !data.found || !data.address) {
					return;
				}

				apply(prefField, 'prefecture', data.address.prefecture);
				apply(cityField, 'city', data.address.city + (data.address.town || ''));

				// 番地は人が入れる。入力途中の邪魔にならないよう、空のときだけ送る。
				if (addressField && addressField.value === '' && document.activeElement === zipField) {
					addressField.focus();
				}
			})
			.catch(function () {
				// 通信失敗時は何もしない。手入力の妨げにしないため、
				// エラー表示も出さない（送信時のサーバー側検証で拾う）。
			});
	}

	function onInput() {
		var digits = normalize(zipField.value);

		if (digits.length === 7) {
			lookup(digits);
		} else {
			lastLookup = '';
		}
	}

	zipField.addEventListener('input', onInput);
	zipField.addEventListener('change', onInput);

	// 入力欄を離れるときに、表示を 000-0000 の形に整える。
	zipField.addEventListener('blur', function () {
		var digits = normalize(zipField.value);

		if (digits.length === 7) {
			zipField.value = digits.slice(0, 3) + '-' + digits.slice(3);
		}
	});
})();
