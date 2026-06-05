#!/usr/bin/env python3
"""
threads_security_post.py  v3.0
───────────────────────────────
曜日に応じて投稿タイプを切り替えて Threads に自動投稿する。

  月・水・金・日 → 自分事（ニュースをもとに現場目線で生成）
  火・木・土     → 記事紹介（cybernote.click の記事を紹介）

ニュースソース:
  - GitHub Advisory Database API
  - CISA KEV（既知悪用脆弱性リスト）
  - NVD CVE API v2

出力: posts/YYYY-MM-DD.md

使い方:
  python threads_security_post.py            # 生成 & Threads へ自動投稿
  python threads_security_post.py --dry-run  # ネットワーク不要の動作確認
  python threads_security_post.py --no-post  # 生成のみ・Threads 投稿はスキップ

環境変数:
  GITHUB_TOKEN            必須（GitHub Actions では自動付与）
  THREADS_ACCESS_TOKEN    必須（Threads への投稿時）
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

# ── 設定 ──────────────────────────────────────────────────────────────────────

OUTPUT_DIR    = Path("posts")
MAX_ITEMS     = 10
LOOKBACK_DAYS = 3

THREADS_API_BASE  = "https://graph.threads.net/v1.0"
CYBERNOTE_RSS_URL = "https://cybernote.click/feed/"

# 月=0 水=2 金=4 日=6 → 自分事 / 火=1 木=3 土=5 → 記事紹介
JIBUNGOTO_DAYS  = {0, 2, 4, 6}
KIJI_SHOKAI_DAYS = {1, 3, 5}

# ── システムプロンプト ─────────────────────────────────────────────────────────

SYSTEM_PROMPT_JIBUNGOTO = """\
あなたはITセキュリティ担当者として日々現場で働くThreadsクリエイターです。
以下のルールを厳守してください。

【投稿スタイル】
- トーン：現場目線のカジュアルな自分事。「セキュリティ担当あるある」「一般人が知らない話」
- 文体：ですます調だが、少し砕けた親しみやすい表現OK
- 文量：4〜6文程度
- 絵文字：1〜2個（冒頭か末尾）
- ハッシュタグ：末尾に3〜4個（#サイバーセキュリティ 必須）

【構成の流れ】
1. 今日のニュースを受けての「現場の感想・気づき」
2. 一般の人が意外と知らない視点や裏話
3. 読者へのさりげないアドバイス

【禁止事項】
- 硬い解説文にしない
- CVSS スコアの数字を断言しない
- 憶測・誇張をしない

出力はJSON形式のみ。
{
  "topic": "投稿のタイトル（25字以内）",
  "post":  "Threads投稿本文（ハッシュタグ含む）",
  "source_url": "参照したニュースのURL"
}
JSON以外の文字列は一切出力しないこと。
"""

SYSTEM_PROMPT_KIJI_SHOKAI = """\
あなたは自分のセキュリティブログ「cybernote.click」を運営するThreadsクリエイターです。
以下のルールを厳守してください。

【投稿スタイル】
- トーン：「こんな記事書きました」「意外と知らない人多いので」的なカジュアルな紹介
- 文体：ですます調だが柔らかく親しみやすく
- 文量：4〜6文程度
- 絵文字：1〜2個（冒頭か末尾）
- ハッシュタグ：末尾に3〜4個（#サイバーセキュリティ 必須）

【構成の流れ】
1. 記事で扱っているテーマをひとことで
2. 「こういう人に読んでほしい」「こんな疑問に答えています」
3. 読者の興味を引く一言＋記事URLへの誘導

【禁止事項】
- 硬い宣伝文にしない
- タイトルをそのまま読み上げない
- URLをそのまま本文に埋め込まない（source_urlに入れる）

出力はJSON形式のみ。
{
  "topic": "記事紹介のタイトル（25字以内）",
  "post":  "Threads投稿本文（ハッシュタグ含む）",
  "source_url": "紹介する記事のURL"
}
JSON以外の文字列は一切出力しないこと。
"""

# ── 曜日判定 ──────────────────────────────────────────────────────────────────

def get_post_type() -> str:
    """今日の曜日から投稿タイプを返す。'jibungoto' or 'kiji_shokai'"""
    weekday = datetime.date.today().weekday()  # 月=0 … 日=6
    return "jibungoto" if weekday in JIBUNGOTO_DAYS else "kiji_shokai"


# ── ニュース収集 ───────────────────────────────────────────────────────────────

def fetch_github_advisories() -> list[dict]:
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


# ── cybernote.click 記事取得 ───────────────────────────────────────────────────

def fetch_cybernote_articles() -> list[dict]:
    """cybernote.click の RSS フィードから記事一覧を取得する。"""
    articles = []
    try:
        r = requests.get(
            CYBERNOTE_RSS_URL,
            timeout=15,
            headers={"User-Agent": "threads-security-bot/1.0"},
        )
        r.raise_for_status()
        root = ET.fromstring(r.content)
        ns = {"content": "http://purl.org/rss/1.0/modules/content/"}
        for item in root.findall(".//item")[:10]:
            title   = item.findtext("title", "").strip()
            link    = item.findtext("link", "").strip()
            desc    = item.findtext("description", "").strip()
            # HTMLタグを除去
            desc = re.sub(r"<[^>]+>", "", desc)[:200]
            if title and link:
                articles.append({"title": title, "url": link, "summary": desc})
    except Exception as e:
        print(f"[WARN] cybernote.click RSS: {e}", file=sys.stderr)
    return articles


# ── 投稿文生成 ─────────────────────────────────────────────────────────────────

def call_gpt(system_prompt: str, user_message: str) -> dict:
    """GitHub Models (GPT-4o) を呼び出してJSONを返す。"""
    api_key = os.environ.get("GITHUB_TOKEN")
    if not api_key:
        print("[ERROR] GITHUB_TOKEN が設定されていません。", file=sys.stderr)
        sys.exit(1)

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
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message},
            ],
        },
        timeout=60,
    )
    r.raise_for_status()

    raw = r.json()["choices"][0]["message"]["content"].strip()
    raw = re.sub(r"```[a-z]*", "", raw).strip("`").strip()
    return json.loads(raw)


def generate_jibungoto(news_items: list[dict]) -> dict:
    """ニュースをもとに自分事スタイルの投稿文を生成する。"""
    news_text = "\n\n".join(
        f"【{i+1}】ソース: {item['source']}\n"
        f"タイトル: {item['title']}\n"
        f"URL: {item['url']}\n"
        f"概要: {item['summary']}"
        for i, item in enumerate(news_items)
    )
    user_message = (
        "以下のセキュリティニュース候補の中から最も「現場感のある話」ができるものを1つ選び、"
        "セキュリティ担当者の自分事として Threads 投稿文を生成してください。\n\n"
        "選定基準:\n"
        "- 日常業務や職場で実際に遭遇しそうなシナリオに結びつけやすい\n"
        "- 一般の人が「知らなかった！」と感じる視点がある\n"
        "- 親しみやすく共感を得やすい\n\n"
        f"【ニュース候補】\n{news_text}"
    )
    return call_gpt(SYSTEM_PROMPT_JIBUNGOTO, user_message)


def generate_kiji_shokai(articles: list[dict]) -> dict:
    """cybernote.click の記事から記事紹介投稿文を生成する。"""
    articles_text = "\n\n".join(
        f"【{i+1}】タイトル: {a['title']}\nURL: {a['url']}\n概要: {a['summary']}"
        for i, a in enumerate(articles)
    )
    user_message = (
        "以下の自分のブログ記事一覧から、今日紹介するのに最も適した記事を1つ選び、"
        "Threads 投稿文を生成してください。\n\n"
        "選定基準:\n"
        "- 多くの人に刺さりやすいテーマ\n"
        "- タイムリーまたは普遍的に役立つ内容\n\n"
        f"【記事一覧】\n{articles_text}"
    )
    return call_gpt(SYSTEM_PROMPT_KIJI_SHOKAI, user_message)


def generate_post(post_type: str, dry_run: bool = False) -> dict:
    """投稿タイプに応じて投稿文を生成する。"""
    if dry_run:
        label = "自分事" if post_type == "jibungoto" else "記事紹介"
        return {
            "topic":      f"DRY-RUN テスト（{label}）",
            "post":       f"[dry-run] {label}の投稿文が入ります。\n#サイバーセキュリティ #テスト",
            "source_url": "https://example.com",
        }

    if post_type == "jibungoto":
        print("📡 ニュースを収集中...")
        news_items = collect_news()
        print(f"   合計 {len(news_items)} 件取得\n")
        if not news_items:
            print("[ERROR] ニュースを取得できませんでした。", file=sys.stderr)
            sys.exit(1)
        print("✍️  GitHub Models (GPT-4o) で自分事投稿を生成中...")
        return generate_jibungoto(news_items)
    else:
        print("📰 cybernote.click から記事を取得中...", end=" ", flush=True)
        articles = fetch_cybernote_articles()
        print(f"{len(articles)}件")
        if not articles:
            print("[ERROR] 記事を取得できませんでした。", file=sys.stderr)
            sys.exit(1)
        print("✍️  GitHub Models (GPT-4o) で記事紹介投稿を生成中...")
        return generate_kiji_shokai(articles)


# ── Threads 自動投稿 ───────────────────────────────────────────────────────────

def post_to_threads(post_text: str, dry_run: bool = False) -> str | None:
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
            "media_type":   "TEXT",
            "text":         post_text,
            "access_token": token,
        },
        timeout=30,
    )
    if not r1.ok:
        print(f"\n[ERROR] コンテナ作成失敗: {r1.status_code} {r1.text}", file=sys.stderr)
        sys.exit(1)

    container_id = r1.json().get("id")
    print(f"OK (container_id={container_id})")

    # STEP 2: 少し待ってから公開
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

def save_post(result: dict, post_type: str, post_id: str | None = None) -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    today_str  = datetime.date.today().isoformat()
    out_path   = OUTPUT_DIR / f"{today_str}.md"
    type_label = "自分事" if post_type == "jibungoto" else "記事紹介"
    posted_line = (
        f"**Threads 投稿ID**: {post_id}" if post_id else "※ 手動投稿または dry-run"
    )

    content = f"""# Threads 投稿文 — {today_str}

## 投稿タイプ
{type_label}

## トピック
{result['topic']}

## 投稿文

{result['post']}

## 参照元
{result['source_url']}

## 投稿ステータス
{posted_line}

---
*Generated by threads_security_post.py v3.0*
"""
    out_path.write_text(content, encoding="utf-8")
    return out_path


# ── エントリポイント ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Threads セキュリティ自動投稿ツール v3.0"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="ネットワーク・API 呼び出しなしで動作確認"
    )
    parser.add_argument(
        "--no-post", action="store_true",
        help="投稿文は生成するが Threads への投稿はスキップ"
    )
    args = parser.parse_args()

    post_type  = get_post_type()
    type_label = "自分事" if post_type == "jibungoto" else "記事紹介"
    weekday_names = ["月", "火", "水", "木", "金", "土", "日"]
    today_weekday = weekday_names[datetime.date.today().weekday()]
    print(f"📅 本日（{today_weekday}曜日）の投稿タイプ: {type_label}\n")

    if args.dry_run:
        print("━━ [DRY-RUN] ネットワーク・API 呼び出しをすべてスキップ ━━")
        result = generate_post(post_type, dry_run=True)
        print(f"\n{'━'*52}")
        print(f"📌 {result['topic']}")
        print()
        print(result["post"])
        print()
        print(f"🔗 {result['source_url']}")
        print(f"{'━'*52}\n")
        out_path = save_post(result, post_type)
        print(f"💾 投稿文を保存 → {out_path}")
        return

    result = generate_post(post_type)

    print(f"\n{'━'*52}")
    print(f"📌 {result['topic']}")
    print()
    print(result["post"])
    print()
    print(f"🔗 {result['source_url']}")
    print(f"{'━'*52}\n")

    post_id = None
    if args.no_post:
        print("⏭️  --no-post のため Threads への投稿をスキップ")
    else:
        print("🚀 Threads に投稿中...")
        post_id = post_to_threads(result["post"])
        if post_id:
            print(f"\n✅ 投稿完了！ post_id={post_id}")

    out_path = save_post(result, post_type, post_id)
    print(f"💾 投稿文を保存 → {out_path}")


if __name__ == "__main__":
    main()
