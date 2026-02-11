# Site Safety Checker リファレンス

## 概要
URLを入力するだけで、そのサイトが詐欺・危険サイトかどうかを多角的にAI分析するツール。
闇バイト、投資詐欺、フィッシング、偽通販、健康詐欺、被害回復詐欺等の特徴パターンをチェックし、6軸レーダーチャートで信頼性を可視化する。

## URL・デプロイ
- **Worker**: `https://site-safety-checker.mizuki-tools.workers.dev`
- **Cloudflareアカウント**: `bd11d6f328847415a6170ccd666e57eb`
- **workers.devサブドメイン**: `mizuki-tools`
- **フロントエンド**: ローカルHTML（`index.html` をブラウザで開く）

## 技術スタック
- Vanilla HTML/CSS/JS（外部依存なし）
- Cloudflare Worker: 対象サイトHTML取得 + Gemini APIプロキシ
- Gemini API（BYOK, gemini-2.5-flash）: コンテンツ分析
- Canvas: レーダーチャート自前描画

## ファイル構成
```
/Users/mizukishirai/claude/check/
├── index.html              # 188行 — 4画面シェル（Setup/Check/Results/Settings）
├── css/style.css           # 493行 — スタイル（レスポンシブ対応）
├── js/app.js               # 1317行 — 全ロジック（IIFE）
├── worker/
│   ├── worker.js           # 184行 — Cloudflare Worker
│   ├── wrangler.toml       # デプロイ設定
│   └── README.md           # デプロイ手順
├── robots.txt              # noindex
└── REFERENCE.md            # 本ファイル
```

## app.js モジュール構成（IIFE内）
| モジュール | 役割 |
|-----------|------|
| Config/Storage | localStorage でAPIキー・Worker URL管理 |
| Router | 4画面切替（Setup/Check/Results/Settings） |
| UrlAnalyzer | クライアント側URL構造分析（不審TLD/ブランド偽装30社/IDNホモグラフ等） |
| HtmlExtractor | DOMParserでコンテンツ抽出（テキスト8000字/フォーム/スクリプト/運営者情報） |
| GeminiClient | Gemini 2.5 Flash構造化出力（6軸スコア + 19カテゴリ詐欺検出 + 7種広告・表示規制違反） |
| ScoreIntegrator | クライアント40%+AI60%ブレンド、リスクレベル判定 |
| RadarChart | Canvas自前描画（Retina対応/6軸六角形/色変化） |
| ProgressMgr | 4段階プログレス + 安全豆知識ローテーション |
| ResultsRenderer | リスクバナー/スコアバー/カテゴリ/所見/総評の描画 |

## 分析フロー
```
URL入力 → クライアント側URL構造分析 → Worker経由でHTML+ヘッダー取得
→ DOMParserでコンテンツ抽出 → Gemini APIで詐欺パターン分析
→ スコア統合 → レーダーチャート+詳細レポート表示
```

## 6軸評価次元（レーダーチャート）
1. **ドメイン信頼性** — URL構造、TLD、ブランド偽装、SSL
2. **コンテンツ安全性** — 不審キーワード、煽り表現、緊急性
3. **運営者透明性** — 特商法表記、会社概要、連絡先、プライバシーポリシー
4. **主張の信頼性** — 誇大広告、非現実的保証、「確実」「絶対」表現
5. **詐欺パターン非合致** — 19カテゴリの既知詐欺パターンとの非類似度
6. **技術的安全性** — SSL、リダイレクト、難読化スクリプト、隠しフォーム

## 検出対象の詐欺・違法サイトカテゴリ（19種）
1. 闇バイト / 2. 投資詐欺 / 3. フィッシング / 4. 偽通販 / 5. 健康詐欺 / 6. 被害回復詐欺 / 7. サポート詐欺 / 8. ロマンス詐欺 / 9. 違法オンラインカジノ / 10. 偽造品・コピー品販売 / 11. 架空請求・ワンクリック詐欺 / 12. 副業・タスク詐欺 / 13. なりすまし広告詐欺 / 14. 仮想通貨・暗号資産詐欺 / 15. 情報商材詐欺 / 16. 闇金・違法貸金業 / 17. 著作権侵害・海賊版 / 18. 還付金詐欺・偽行政サイト / 19. 霊感商法・スピリチュアル詐欺・疑似科学

## プロンプト構造（重複排除・最適化済み）
- **回答ルール（冒頭配置）** — 反ハルシネーション6ルール。LLMが最初に読む位置に配置し遵守率を向上。
- **19カテゴリ（法令違反を内包）** — Cat5に薬機法/景表法/医療広告/あはき法統合、Cat13にAIディープフェイク/JFC統合、Cat2に金融庁統合、Cat19に霊感商法/占い詐欺/疑似科学(水素水/マイナスイオン/ゲルマニウム/EM菌)統合。重複なし。
- **広告・表示規制違反（7項目）** — 19カテゴリに属さない横断的な法令違反パターン: No.1表示/効果なし商品/二重価格/ステマ/打消し/定期購入/グリーンウォッシュ。

## スコア統合ルール
- domain_trust, tech_safety: クライアント40% + AI60%
- 他4次元: AI100%
- 総合リスク: 平均80以上→safe, 60→low, 40→medium, 20→high, それ以下→critical
- 2次元以上が15以下 or scam_pattern15以下 → 最低high（単一軸低スコアのみではsafe→lowにナッジ）

## Worker エンドポイント
| パス | メソッド | 説明 |
|------|----------|------|
| `/fetch?url=<encoded>` | GET | 対象サイトHTML取得（200KB上限、10秒タイムアウト、SSRF防止） |
| `/models/*` | POST | Gemini APIパススルー（CORS対応） |
| `/health` | GET | ヘルスチェック |

## カラースキーム
- Primary: `#4A6FA5`（スチールブルー）
- Background: `#F5F7FA`
- Safe: `#27AE60` / Warning: `#F39C12` / Danger: `#E74C3C`

## エラーハンドリング
- Worker取得失敗 → URL分析のみの部分結果表示
- Gemini失敗 → HTML抽出結果のみ表示（AI分析なし）
- 常に可能な範囲の結果を表示、未完了ステージを明示

## Workerデプロイ手順
```bash
cd /Users/mizukishirai/claude/check/worker
wrangler deploy
```
