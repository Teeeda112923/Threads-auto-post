# threads-auto-post v2.0

セキュリティニュースを毎日自動収集し、Claude API で Threads 投稿文を生成、
Threads API で自動投稿するツールです。

## 仕組み

```
GitHub Actions（毎日 JST 20:00）
  ↓
ニュース収集
  ├─ GitHub Advisory Database API
  ├─ CISA KEV（既知悪用脆弱性リスト）
  └─ NVD CVE API v2（直近の CRITICAL 脆弱性）
  ↓
Claude API で日本語 Threads 投稿文を生成
  ↓
Threads API で自動投稿
  ↓
posts/YYYY-MM-DD.md にコミット保存
```

## セットアップ

### 1. リポジトリを作成してプッシュ

```bash
git init
git add .
git commit -m "initial commit"
git remote add origin https://github.com/<アカウント>/threads-auto-post.git
git push -u origin main
```

### 2. GitHub Secrets を登録（3つ）

**Settings → Secrets and variables → Actions** で以下を追加：

| Secret 名              | 値の取得方法                                      |
|------------------------|--------------------------------------------------|
| `ANTHROPIC_API_KEY`    | Anthropic コンソールから取得                      |
| `THREADS_ACCESS_TOKEN` | Meta for Developers でトークン生成               |
| `THREADS_USER_ID`      | 下記コマンドで取得                                |

#### THREADS_USER_ID の取得方法

ブラウザのアドレスバーに以下を貼り付けてアクセス：

```
https://graph.threads.net/v1.0/me?fields=id,username&access_token=【アクセストークン】
```

表示された JSON の `"id"` の値が THREADS_USER_ID です。

### 3. GitHub Actions を有効化

リポジトリの **Actions タブ** を開いてワークフローを有効化。
毎日 JST 20:00 に自動実行されます。

手動で今すぐ実行：
**Actions → 毎日 Threads 自動投稿 → Run workflow**

## ローカルでの実行

```bash
pip install requests anthropic

# 通常実行（生成 & Threads 投稿）
export ANTHROPIC_API_KEY=sk-ant-...
export THREADS_ACCESS_TOKEN=THAA...
export THREADS_USER_ID=1234567890
python threads_security_post.py

# 投稿文だけ生成（Threads への投稿はしない）
python threads_security_post.py --no-post

# ニュース取得だけ確認（API 呼び出しなし）
python threads_security_post.py --dry-run
```

## オプション一覧

| オプション  | 動作                                         |
|-------------|----------------------------------------------|
| なし        | ニュース収集 → 投稿文生成 → Threads 自動投稿 |
| `--no-post` | ニュース収集 → 投稿文生成のみ（投稿しない）  |
| `--dry-run` | ニュース取得のみ確認（API 呼び出しなし）      |

## ⚠️ トークンの期限について

Threads アクセストークンは **約60日で期限切れ**になります。
期限が切れたら Meta for Developers でトークンを再発行し、
GitHub Secrets の `THREADS_ACCESS_TOKEN` を更新してください。

## ライセンス

MIT
