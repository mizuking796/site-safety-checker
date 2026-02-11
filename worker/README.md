# Site Safety Checker Worker デプロイ手順

## 前提
- Cloudflare アカウント
- Wrangler CLI (`npm install -g wrangler`)

## セットアップ

1. **Wrangler ログイン**
```bash
wrangler login
```

2. **Worker プロジェクト初期化**
```bash
cd /Users/mizukishirai/claude/check/worker
wrangler init site-safety-worker --from-dash  # 既存なら
# または新規:
```

3. **wrangler.toml 作成**
```toml
name = "site-safety-checker"
main = "worker.js"
compatibility_date = "2024-01-01"
```

4. **デプロイ**
```bash
wrangler deploy
```

5. **動作確認**
```bash
curl https://site-safety-checker.<your-subdomain>.workers.dev/health
```

## エンドポイント

| パス | メソッド | 説明 |
|------|----------|------|
| `/fetch?url=<encoded>` | GET | 対象サイトHTML取得 |
| `/models/*` | POST | Gemini APIプロキシ |
| `/health` | GET | ヘルスチェック |

## 制限事項
- HTML取得: 最大200KB
- タイムアウト: 10秒
- プライベートIPアドレスはブロック（SSRF防止）
