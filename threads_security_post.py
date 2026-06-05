#!/usr/bin/env python3
"""
threads_security_post.py  v2.0
───────────────────────────────
セキュリティニュースを複数ソースから収集し、
GitHub Models (GPT-4o) で Threads 投稿文を生成 → Threads API で自動投稿する。

ニュースソース:
  - GitHub Advisory Database API
  - CISA KEV（既知悪用脆弱性リスト）
  - NVD CVE API v2

出力: posts/YYYY-MM-DD.md（投稿文をファイルにも保存）

使い方:
  python threads_security_post.py            # 生成 & Threads へ自動投稿
  python threads_security_post.py --dry-run  # API 呼び出しなし（ニュース取得のみ確認）
  python threads_security_post.py --no-post  # 生成のみ・Threads 投稿はスキップ

環境変数:
  GITHUB_TOKEN            必須（GitHub Actions では自動付与）
  THREADS_ACCESS_TOKEN    必須（Threads への投稿時・ユーザーIDはトークンから自動取得）
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

# ── 設定 ──────────────────────────────────────────────────────────────────────

OUTPUT_DIR    = Path("posts")
MAX_ITEMS     = 10   # Claude に渡す候補数上限
LOOKBACK_DAYS = 3    # 何日前までのニュースを対象にするか

THREADS_API_BASE = "https://graph.threads.net/v1.0"

SYSTEM_PROMPT = """\
あなたはITセキュリティ専門家でThreadsクリエイターです。
以下のルールを厳守してください。

【投稿スタイル】
- トーン：落ち着いた解説系。専門家らしい信頼感・わかりやすさを両立する
- 文体：ですます調
- 文量：5〜8文程度
- 絵文字：1〜2個のみ（冒頭か末尾）
- ハッシュタグ：投稿末尾に3〜4個（#サイバーセキュリティ 必須）

【構成の流れ】
1. 何が起きたか（ファクト・影響するソフト・バージョン）
2. なぜ重要か・影響範囲（誰が困るか）
3. 読者が今日できる対策や注目ポイント

【禁止事項】
- キーワードを「」で囲まない
- 憶測・誇張をしない
- CVSS スコアの数字を断言しない（「深刻度が高い」程度の表現にとどめる）

出力はJSON形式のみ。以下のキーを持つオブジェクトを返してください。
{
  "topic": "ニュースのタイトル（25字以内）",
  "post":  "Threads投稿本文（ハッシュタグ含む）",
  "source_url": "参照したニュースのURL"
}
JSON以外の文字列（前置き・説明・コードブロック記号など）は一切出力しないこと。
"""


# ── ニュース収集 ───────────────────────────────────────────────────────────────

def fetch_github_advisories() -> list[dict]:
    """GitHub Advisory Database API から最新レビュー済み脆弱性を取得する。"""
    items = []
    url = (
        "https://api.github.com/advisories"
        "?per_page=10&type=reviewed&order=desc&sort=updated"
    )
    headers = {
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":           "threads-security-bot/1.0",
    }
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        for adv in r.json():
            items.append({
                "source":  "GitHub Advisory",
                "title":   adv.get("summary", ""),
                "url":     adv.get("html_url", ""),
                "summary": (
                    f"重大度: {adv.get('severity', 'unknown')} / "
                    f"CWE: {','.join(c.get('cwe_id','') for c in adv.get('cwes', [])[:2])} / "
                    f"影響パッケージ: "
                    + ", ".join(
                        v.get("package", {}).get("name", "")
                        for v in adv.get("vulnerabilities", [])[:3]
                    )
                ),
            })
    except Exception as e:
        print(f"[WARN] GitHub Advisory: {e}", file=sys.stderr)
    return items


def fetch_cisa_kev() -> list[dict]:
    """CISA KEV（既知悪用脆弱性リスト）の最新追加分を取得する。"""
    items = []
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "threads-security-bot/1.0"})
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        vulns_sorted = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
        cutoff = (datetime.date.today() - datetime.timedelta(days=LOOKBACK_DAYS)).isoformat()
        for v in vulns_sorted[:10]:
            if v.get("dateAdded", "") < cutoff:
                break
            items.append({
                "source":  "CISA KEV",
                "title":   f"{v.get('cveID','')} {v.get('vulnerabilityName','')}",
                "url":     "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "summary": (
                    f"製品: {v.get('product','')} ({v.get('vendorProject','')}) / "
                    f"追加日: {v.get('dateAdded','')} / "
                    f"悪用確認済み / 期限: {v.get('dueDate','')}"
                ),
            })
    except Exception as e:
        print(f"[WARN] CISA KEV: {e}", file=sys.stderr)
    return items


def fetch_nvd_recent() -> list[dict]:
    """NVD CVE API v2 から直近の CRITICAL CVE を取得する。"""
    items = []
    today = datetime.date.today()
    start = (today - datetime.timedelta(days=LOOKBACK_DAYS)).isoformat() + "T00:00:00.000"
    end   = today.isoformat() + "T23:59:59.000"
    url   = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start}&pubEndDate={end}"
        "&cvssV3Severity=CRITICAL&resultsPerPage=10"
    )
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "threads-security-bot/1.0"})
        r.raise_for_status()
        for item in r.json().get("vulnerabilities", []):
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs  = cve.get("descriptions", [])
            desc   = next((d["value"] for d in descs if d["lang"] == "en"), "")
            refs   = cve.get("references", [])
            link   = refs[0]["url"] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            items.append({
                "source":  "NVD",
                "title":   cve_id,
                "url":     link,
                "summary": desc[:250],
            })
    except Exception as e:
        print(f"[WARN] NVD: {e}", file=sys.stderr)
    return items


def collect_news() -> list[dict]:
    """全ソースからニュースを収集してまとめて返す。"""
    print("  → GitHub Advisory Database...", end=" ", flush=True)
    gh = fetch_github_advisories()
    print(f"{len(gh)}件")
    time.sleep(1)

    print("  → CISA KEV...", end=" ", flush=True)
    kev = fetch_cisa_kev()
    print(f"{len(kev)}件")
    time.sleep(1)

    print("  → NVD CVE API...", end=" ", flush=True)
    nvd = fetch_nvd_recent()
    print(f"{len(nvd)}件")

    all_items = gh + kev + nvd
    seen, unique = set(), []
    for item in all_items:
        if item["url"] not in seen:
            seen.add(item["url"])
            unique.append(item)

    return unique[:MAX_ITEMS]


# ── 投稿文生成 ─────────────────────────────────────────────────────────────────

def generate_post(news_items: list[dict], dry_run: bool = False) -> dict:
    """Claude API に候補ニュースを渡して投稿文を生成する。"""
    if dry_run:
        return {
            "topic":      "DRY-RUN テスト",
            "post":       "[dry-run] ここに投稿文が入ります。\n#サイバーセキュリティ #テスト",
            "source_url": "https://example.com",
        }

    api_key = os.environ.get("GITHUB_TOKEN")
    if not api_key:
        print("[ERROR] GITHUB_TOKEN が設定されていません。", file=sys.stderr)
        sys.exit(1)

    news_text = "\n\n".join(
        f"【{i+1}】ソース: {item['source']}\n"
        f"タイトル: {item['title']}\n"
        f"URL: {item['url']}\n"
        f"概要: {item['summary']}"
        for i, item in enumerate(news_items)
    )

    user_message = (
        "以下のセキュリティニュース候補の中から、今日投稿する価値が最も高いものを1つ選び、"
        "Threads 投稿文を生成してください。\n\n"
        "選定基準:\n"
        "- 影響範囲が広い（多くのユーザーや企業に関係する）\n"
        "- 悪用が確認済み or 深刻度が高い\n"
        "- 日本語圏の読者にとって身近なソフト・サービスに関係する\n\n"
        f"【ニュース候補】\n{news_text}"
    )

    r = requests.post(
        "https://models.inference.ai.azure.com/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        },
        json={
            "model":      "gpt-4o",
            "max_tokens": 1024,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_message},
            ],
        },
        timeout=60,
    )
    r.raise_for_status()

    raw = r.json()["choices"][0]["message"]["content"].strip()
    raw = re.sub(r"```[a-z]*", "", raw).strip("`").strip()
    return json.loads(raw)


# ── Threads 自動投稿 ───────────────────────────────────────────────────────────

def post_to_threads(post_text: str, dry_run: bool = False) -> str | None:
    """
    Threads API を使って投稿する。
    成功した場合は投稿IDを返す。dry_run の場合は None を返す。

    手順:
      1. メディアコンテナを作成（テキスト投稿の場合は media_type=TEXT）
      2. コンテナを公開
    """
    if dry_run:
        print("  [dry-run] Threads への投稿をスキップ")
        return None

    token = os.environ.get("THREADS_ACCESS_TOKEN")

    if not token:
        print("[ERROR] THREADS_ACCESS_TOKEN が設定されていません。", file=sys.stderr)
        sys.exit(1)

    # トークンからユーザーIDを自動取得
    me = requests.get(
        f"{THREADS_API_BASE}/me",
        params={"fields": "id,username", "access_token": token},
        timeout=15,
    )
    if not me.ok:
        print(f"\n[ERROR] ユーザーID取得失敗: {me.status_code} {me.text}", file=sys.stderr)
        sys.exit(1)
    user_id = me.json()["id"]
    print(f"  → Threads ユーザーID: {user_id}")

    # STEP 1: メディアコンテナを作成
    print("  → Threads メディアコンテナを作成中...", end=" ", flush=True)
    r1 = requests.post(
        f"{THREADS_API_BASE}/{user_id}/threads",
        params={
            "media_type":    "TEXT",
            "text":          post_text,
            "access_token":  token,
        },
        timeout=30,
    )
    if not r1.ok:
        print(f"\n[ERROR] コンテナ作成失敗: {r1.status_code} {r1.text}", file=sys.stderr)
        sys.exit(1)

    container_id = r1.json().get("id")
    print(f"OK (container_id={container_id})")

    # STEP 2: 少し待ってから公開（Meta 推奨: 数秒待つ）
    time.sleep(5)

    print("  → Threads に公開中...", end=" ", flush=True)
    r2 = requests.post(
        f"{THREADS_API_BASE}/{user_id}/threads_publish",
        params={
            "creation_id":  container_id,
            "access_token": token,
        },
        timeout=30,
    )
    if not r2.ok:
        print(f"\n[ERROR] 公開失敗: {r2.status_code} {r2.text}", file=sys.stderr)
        sys.exit(1)

    post_id = r2.json().get("id")
    print(f"OK (post_id={post_id})")
    return post_id


# ── ファイル保存 ───────────────────────────────────────────────────────────────

def save_post(result: dict, post_id: str | None = None) -> Path:
    """生成した投稿文を Markdown ファイルに保存する。"""
    OUTPUT_DIR.mkdir(exist_ok=True)
    today_str = datetime.date.today().isoformat()
    out_path  = OUTPUT_DIR / f"{today_str}.md"

    posted_line = (
        f"**Threads 投稿ID**: {post_id}"
        if post_id
        else "※ 手動投稿または dry-run"
    )

    content = f"""# Threads 投稿文 — {today_str}

## トピック
{result['topic']}

## 投稿文

{result['post']}

## 参照元
{result['source_url']}

## 投稿ステータス
{posted_line}

---
*Generated by threads_security_post.py v2.0*
"""
    out_path.write_text(content, encoding="utf-8")
    return out_path


# ── エントリポイント ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Threads セキュリティニュース自動投稿ツール v2.0"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="API 呼び出しなしでニュース取得のみ確認"
    )
    parser.add_argument(
        "--no-post", action="store_true",
        help="投稿文は生成するが Threads への投稿はスキップ"
    )
    args = parser.parse_args()

    if args.dry_run:
        print("━━ [DRY-RUN] ネットワーク・API 呼び出しをすべてスキップ ━━")
        result = generate_post([], dry_run=True)
        print(f"\n{'━'*52}")
        print(f"📌 {result['topic']}")
        print()
        print(result["post"])
        print()
        print(f"🔗 {result['source_url']}")
        print(f"{'━'*52}\n")
        out_path = save_post(result)
        print(f"💾 投稿文を保存 → {out_path}")
        return

    # ── ニュース収集 ──
    print("📡 ニュースを収集中...")
    news_items = collect_news()
    print(f"   合計 {len(news_items)} 件取得\n")

    if not news_items:
        print("[ERROR] ニュースを取得できませんでした。", file=sys.stderr)
        sys.exit(1)

    # ── 投稿文生成 ──
    print("✍️  GitHub Models (GPT-4o) で投稿文を生成中...")
    result = generate_post(news_items)

    print(f"\n{'━'*52}")
    print(f"📌 {result['topic']}")
    print()
    print(result["post"])
    print()
    print(f"🔗 {result['source_url']}")
    print(f"{'━'*52}\n")

    # ── Threads 投稿 ──
    post_id = None
    if args.no_post:
        print("⏭️  --no-post のため Threads への投稿をスキップ")
    else:
        print("🚀 Threads に投稿中...")
        post_id = post_to_threads(result["post"])
        if post_id:
            print(f"\n✅ 投稿完了！ post_id={post_id}")

    # ── ファイル保存 ──
    out_path = save_post(result, post_id)
    print(f"💾 投稿文を保存 → {out_path}")


if __name__ == "__main__":
    main()
