/**
 * サイト共通のふるまい。
 *
 * 依存ライブラリなし。jQuery も読み込んでいない（WordPress 同梱版に
 * 引きずられないようにするため）。
 */
(function () {
	'use strict';

	/* --- ハンバーガーメニュー ----------------------------- */

	var toggle = document.getElementById('nav-toggle');
	var nav = document.getElementById('global-nav');

	if (toggle && nav) {
		var setNav = function (open) {
			toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
			nav.classList.toggle('is-open', open);
			document.body.classList.toggle('is-nav-open', open);

			var label = toggle.querySelector('.u-visually-hidden');
			if (label) {
				label.textContent = open ? 'メニューを閉じる' : 'メニューを開く';
			}
		};

		toggle.addEventListener('click', function () {
			setNav(toggle.getAttribute('aria-expanded') !== 'true');
		});

		// ドロワー内のリンクを押したら閉じる。
		nav.addEventListener('click', function (event) {
			if (event.target.closest('a')) {
				setNav(false);
			}
		});

		// Esc で閉じる。
		document.addEventListener('keydown', function (event) {
			if (event.key === 'Escape' && toggle.getAttribute('aria-expanded') === 'true') {
				setNav(false);
				toggle.focus();
			}
		});

		// PC 幅に戻したときに開いたままにしない。
		var mq = window.matchMedia('(min-width: 768px)');
		var onChange = function (event) {
			if (event.matches) {
				setNav(false);
			}
		};

		if (typeof mq.addEventListener === 'function') {
			mq.addEventListener('change', onChange);
		} else if (typeof mq.addListener === 'function') {
			mq.addListener(onChange);
		}
	}

	/* --- ページトップ ------------------------------------- */

	var pagetop = document.getElementById('pagetop');

	if (pagetop) {
		var threshold = 400;
		var ticking = false;

		var update = function () {
			pagetop.classList.toggle('is-visible', window.scrollY > threshold);
			ticking = false;
		};

		window.addEventListener('scroll', function () {
			if (!ticking) {
				window.requestAnimationFrame(update);
				ticking = true;
			}
		}, { passive: true });

		pagetop.addEventListener('click', function () {
			var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
			window.scrollTo({ top: 0, behavior: reduce ? 'auto' : 'smooth' });
		});

		update();
	}
})();
