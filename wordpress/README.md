# コーポレートサイト WordPress テーマ（初期公開7ページ）

名古屋の製造業クライアント向けコーポレートサイト。Illustrator 入稿デザインを
再現するカスタムテーマ一式です。**既製テーマ・購入テーマ・テーマフレームワークは
一切使用していません。** 素の WordPress にこのテーマだけを入れれば動きます。

## 構成

```
wordpress/
├── docker-compose.yml          ローカル開発環境（WordPress + MariaDB + Mailpit）
├── dev/mu-plugins/             開発用のみ。納品対象外
├── docs/
│   ├── DESIGN-HANDOFF.md       AI 入稿データ → コードの対応表。ピクセル調整の手順
│   └── DEPLOY.md               本番サーバーへの反映手順
└── wp-content/themes/seizo/    ★納品物はこのディレクトリ一式
```

## ローカルで動かす

必要なのは Docker のみ（PHP / MySQL / Node のインストールは不要）。

```bash
cd wordpress
docker compose up -d
```

| URL | 内容 |
| --- | --- |
| http://localhost:8080 | サイト |
| http://localhost:8080/wp-admin/ | 管理画面 |
| http://localhost:8025 | 送信メールの確認（Mailpit） |

初回のみ WordPress のインストール画面が出ます。言語に「日本語」を選び、
サイト名・管理ユーザーを設定してください。その後:

1. 管理画面 → 外観 → テーマ → **Seizo Corporate** を「有効化」
2. 有効化した時点で、7ページ・メニュー・お知らせカテゴリーが自動生成されます
3. 設定 → パーマリンク → 「投稿名」を選んで保存（お知らせの URL に必要）

`docker compose down -v` で DB ごと破棄してやり直せます。

## ページ構成（今フェーズ公開分）

| ページ | URL | テンプレート | CMS 編集 |
| --- | --- | --- | --- |
| トップ | `/` | `front-page.php` | — |
| 会社概要 | `/company/` | `page-company.php` | — |
| 事業・製品 | `/business/` | `page-business.php` | — |
| 品質・技術 | `/quality/` | `page-quality.php` | — |
| 採用情報 | `/recruit/` | `page-recruit.php` | — |
| お問い合わせ | `/contact/` | `page-contact.php` | — |
| お知らせ | `/news/` ほか | `archive-news.php` / `single-news.php` | **○** |

補助ページとして個人情報保護方針（`/privacy/`）と 404 を用意しています。

### CMS 編集範囲

今フェーズでクライアントが更新するのは **お知らせのみ** です。
管理画面は権限に応じて絞り込んであり、管理者以外には「お知らせ」「メディア」
以外のメニューを表示しません（`inc/admin.php`）。ダッシュボードには更新手順を
載せた案内ウィジェットを常設しています。

他のページの文言はテンプレート内の配列にまとまっているので、次フェーズで
CMS 化する場合もマークアップを触らずに移行できます。

## 実装した機能

### お問い合わせフォーム（プラグイン不使用）

`inc/contact.php` + `page-contact.php`。

- **入力 → 確認 → 完了** の3画面（日本のコーポレートサイトの慣習に合わせた構成）
- 送信後は PRG リダイレクトでリロードによる二重送信を防止
- nonce 検証、ハニーポット、送信までの経過時間チェック、IP 単位のレート制限
- サーバー側で全項目を検証（メール形式・電話番号・郵便番号・カナ・文字数）
- 管理者宛の通知メールと、送信者への自動返信
- 項目の追加・削除は `seizo_contact_fields()` の配列1か所で完結

### 郵便番号 → 住所の自動入力

`inc/zipcode.php` + `assets/js/contact.js`。

郵便番号を7桁入力した時点で都道府県・市区町村を自動補完し、番地欄へフォーカスを移します。

ブラウザから外部 API を直接叩かず、**WordPress 側の REST エンドポイントを経由**
させています（`/wp-json/seizo/v1/zipcode/4600008`）。CORS に依存せず、結果は
サーバー側に1か月キャッシュされるため、同じ番号で外部へ出ていきません。

クライアントのサーバーが外向き通信を制限している場合は、`seizo_zipcode_provider`
フィルタでローカルの住所テーブルを返す実装に差し替えられます。フロント側の
変更は不要です。

### そのほか

- 全ページレスポンシブ（SP はドロワーメニュー）
- パンくず、ページ送り、前後記事ナビ
- スキップリンク、`aria-*`、フォーカス表示、`prefers-reduced-motion` 対応
- 出力は `esc_html()` / `esc_url()` / `esc_attr()` で統一

## 技術方針

**ビルド工程を持たせていません。** CSS は素の CSS、JS は依存なしの素の JS です。

- 入稿 AI と突き合わせるとき、ブラウザで見ている CSS とリポジトリの CSS が
  1対1で対応していないとピクセル調整の往復が増えるため
- 納品先がクライアントの既存サーバーで、Node を前提にできないため
- 保守フェーズで別の担当者が触る場合も、FTP で上げ直せば済むため

CSS は `tokens.css`（デザイン値）→ `base.css` → `components.css` → `pages.css`
の順に読み込みます。色・級数・余白の最終調整は **`tokens.css` だけ** で完結します。
詳細は [docs/DESIGN-HANDOFF.md](docs/DESIGN-HANDOFF.md)。

## 納品前の差し替え箇所

コード中に `★要差し替え` / `★入稿差し替え` のコメントを入れてあります。

```bash
grep -rn "★" wp-content/themes/seizo/
```

主なもの:

| 箇所 | 内容 |
| --- | --- |
| `inc/setup.php` の `seizo_company()` | 社名・住所・電話番号・現行サイト URL |
| `assets/css/tokens.css` | AI のスウォッチ・級数・余白 |
| `assets/img/` | AI から書き出した画像 |
| 各 `page-*.php` の配列 | 沿革・設備一覧・募集要項などの原稿 |
| `wp-config.php` | `SEIZO_CONTACT_TO`（問い合わせ通知の宛先） |

## 検証

```bash
# ロジックの検証（WordPress の起動不要。36 項目）
php tests/run.php

# PHP 構文チェック
find wp-content/themes/seizo -name "*.php" -exec php -l {} \;

# JS 構文チェック
node --check wp-content/themes/seizo/assets/js/site.js
node --check wp-content/themes/seizo/assets/js/contact.js
```

`tests/run.php` は WordPress の関数をスタブ化して、フォームの入力検証・
ボット対策・レート制限・メールヘッダの安全性・郵便番号の検索とキャッシュを
確認します。実ブラウザでの表示確認は `docker compose up -d` で行ってください。
