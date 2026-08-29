#!/usr/bin/env python3
"""
daisuke-healthcare の暗号化／復号ツール

  python3 crypt.py extract   リポジトリの暗号化ファイル → src/ に平文で展開
  python3 crypt.py build     src/ の平文 → リポジトリ直下に暗号化して出力

パスフレーズは環境変数 SITE_PW から取るか、なければ実行時に入力を求める。
コード・README・コミット・ログには絶対に書かないこと。

依存: pip install cryptography markdown

暗号方式: PBKDF2-HMAC-SHA256（250,000回, 16byteソルト）で鍵導出 → AES-256-GCM（12byte IV）

--------------------------------------------------------------------------
扱うもの
--------------------------------------------------------------------------
  ■ 公開ページ（ブラウザでパスフレーズを入れると読める gate ページ）
      index / routine / dashboard / bowl / leucine   … src/*.html を手で編集
      profile                                        … 正本mdから自動生成（手で編集しない）

  ■ ドキュメント（暗号化して保存するだけ。ブラウザでは開かない）
      profile.md.enc   ← src/健康管理プロファイル.md   ★これが正本
      trainlog.md.enc  ← src/トレログ.md

  正本は src/健康管理プロファイル.md ただ1つ。profile.html はその派生物なので、
  内容を変えるときは必ず md を編集して build し直す。
"""
import os
import re
import sys
import json
import base64
import hashlib
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
ITER = 250_000

# 手で編集する gate ページ
PAGES = ["index.html", "routine.html", "dashboard.html", "bowl.html", "leucine.html", "protein.html"]
# 正本mdから自動生成する gate ページ（extract しない。build で必ず作り直す）
GENERATED = ["profile.html"]
ALL_PAGES = PAGES + GENERATED

# 暗号化して保存するドキュメント: 出力名 → src/ 内のファイル名
DOCS = {
    "profile.md.enc": "健康管理プロファイル.md",
    "trainlog.md.enc": "トレログ.md",
}
PROFILE_MD = "健康管理プロファイル.md"

TITLES = {
    "index.html": "健康管理ハブ",
    "routine.html": "コンディショニングルーチン",
    "dashboard.html": "健康管理ダッシュボード",
    "bowl.html": "昼ボウルの栄養設計",
    "leucine.html": "ロイシン閾値と食事設計",
    "protein.html": "プロテイン比較",
    "profile.html": "健康管理プロファイル（正本）",
}

PAYLOAD_RE = re.compile(r'const D=\{s:"([^"]+)",i:"([^"]+)",c:"([^"]+)",n:(\d+)\}')

GATE = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>__TITLE__</title>
<style>
  :root{--bg:#eff0f4;--card:#fff;--ink:#16181f;--muted:#6f7285;--line:#dcdee7;--accent:#9c2f5c}
  @media(prefers-color-scheme:dark){:root{--bg:#101219;--card:#191c25;--ink:#eceef4;--muted:#8e93a6;--line:#2c313e;--accent:#e88cb0}}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--ink);font-family:"Hiragino Sans","Yu Gothic UI",system-ui,sans-serif;
       min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .box{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px 26px;max-width:360px;width:100%;
       box-shadow:0 1px 2px rgba(0,0,0,.05),0 10px 30px rgba(0,0,0,.07);display:flex;flex-direction:column;gap:14px}
  h1{font-size:17px;font-weight:700;line-height:1.5}
  p{font-size:13px;color:var(--muted);line-height:1.7}
  input{width:100%;padding:11px 13px;font-size:16px;border:1.5px solid var(--line);border-radius:10px;
        background:var(--bg);color:var(--ink);font-family:inherit}
  input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
  button{width:100%;padding:11px;font-size:14px;font-weight:700;border:none;border-radius:10px;
         background:var(--accent);color:#fff;cursor:pointer;font-family:inherit}
  button:disabled{opacity:.5;cursor:default}
  .err{font-size:13px;color:var(--accent);font-weight:600;min-height:18px}
</style>
</head>
<body>
<div class="box">
  <h1>__TITLE__</h1>
  <p>パスワードを入力してください。</p>
  <input id="p" type="password" autocomplete="current-password" placeholder="パスワード" autofocus>
  <button id="b">開く</button>
  <div class="err" id="e"></div>
</div>
<script>
const D={s:"__SALT__",i:"__IV__",c:"__CT__",n:__ITER__};
const b2a=b=>Uint8Array.from(atob(b),c=>c.charCodeAt(0));
async function open_(pw){
  const enc=new TextEncoder();
  const base=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey(
    {name:"PBKDF2",salt:b2a(D.s),iterations:D.n,hash:"SHA-256"},
    base,{name:"AES-GCM",length:256},false,["decrypt"]);
  const buf=await crypto.subtle.decrypt({name:"AES-GCM",iv:b2a(D.i)},key,b2a(D.c));
  const html=new TextDecoder().decode(buf);
  try{sessionStorage.setItem("dw_k",pw)}catch(e){}
  document.open();document.write(html);document.close();
}
const btn=document.getElementById("b"),inp=document.getElementById("p"),err=document.getElementById("e");
async function go(){
  btn.disabled=true;err.textContent="";
  try{await open_(inp.value)}
  catch(e){err.textContent="パスワードが違います";btn.disabled=false;inp.select()}
}
btn.onclick=go;
inp.onkeydown=e=>{if(e.key==="Enter")go()};
(async()=>{try{const k=sessionStorage.getItem("dw_k");if(k){await open_(k)}}catch(e){}})();
</script>
</body>
</html>"""

# 正本md → HTML のラッパ（読む専用。長文・表が多いのでモバイルで横スクロールできるようにする）
DOC_SHELL = """<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>__TITLE__</title>
<style>
 :root{--bg:#f7f6f3;--card:#fff;--ink:#1c212b;--sub:#68707d;--line:#e4e1da;--accent:#9c2f5c;--accent-soft:#fbeef3;--code:#f2f0ec}
 @media(prefers-color-scheme:dark){:root{--bg:#101219;--card:#191c25;--ink:#eceef4;--sub:#9aa0b0;--line:#2c313e;--accent:#e88cb0;--accent-soft:#2a1a22;--code:#12151d}}
 *{box-sizing:border-box;margin:0;padding:0}
 body{background:var(--bg);color:var(--ink);line-height:1.85;padding:28px 16px 80px;
      font-family:"Hiragino Sans","Yu Gothic UI","Noto Sans JP",system-ui,sans-serif;font-size:15px;
      -webkit-text-size-adjust:100%}
 .w{max-width:820px;margin:0 auto}
 .bar{position:sticky;top:0;z-index:9;background:var(--bg);padding:8px 0 12px;margin-bottom:8px;border-bottom:1px solid var(--line)}
 .bar a{font-size:13px;font-weight:700;color:var(--accent);text-decoration:none}
 h1{font-size:23px;margin:14px 0 6px;line-height:1.45}
 h2{font-size:19px;margin:38px 0 10px;padding-top:16px;border-top:2px solid var(--line);line-height:1.45}
 h3{font-size:16px;margin:24px 0 6px;color:var(--accent);line-height:1.5}
 h4{font-size:14.5px;margin:18px 0 4px}
 p{margin:9px 0}
 ul,ol{margin:9px 0 9px 1.3em}
 li{margin:5px 0}
 li>ul,li>ol{margin:4px 0 4px 1.1em}
 strong,b{font-weight:700}
 hr{border:none;border-top:1px solid var(--line);margin:26px 0}
 code{background:var(--code);border-radius:5px;padding:1px 6px;font-size:13px;
      font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
 pre{background:var(--code);border:1px solid var(--line);border-radius:10px;padding:13px 15px;margin:12px 0;
     overflow-x:auto;line-height:1.7}
 pre code{background:none;padding:0;font-size:12.5px}
 .tw{overflow-x:auto;margin:12px 0;-webkit-overflow-scrolling:touch}
 table{border-collapse:collapse;width:100%;min-width:420px;font-size:13.5px;background:var(--card)}
 th,td{border:1px solid var(--line);padding:8px 11px;text-align:left;vertical-align:top;line-height:1.7}
 th{background:var(--accent-soft);font-weight:700;white-space:nowrap}
 blockquote{border-left:3px solid var(--accent);background:var(--card);margin:12px 0;padding:9px 15px;color:var(--sub)}
 a{color:var(--accent);word-break:break-all}
 del{color:var(--sub)}
 footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--line);color:var(--sub);font-size:12px}
</style></head><body><div class="w">
<div class="bar"><a href="index.html">&larr; 健康管理ハブ</a></div>
__BODY__
<footer>これが正本。原本は <code>src/健康管理プロファイル.md</code> で、このページはその派生物。
内容を変えるときは md を編集して <code>crypt.py build</code> で作り直す。</footer>
</div></body></html>"""


def get_password() -> str:
    pw = os.environ.get("SITE_PW") or getpass.getpass("パスフレーズ: ")
    if len(pw) < 16:
        sys.exit("パスフレーズが短すぎます。16文字以上・単語2つ以上にしてください。")
    return pw


def derive(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITER, 32)


def seal(pw: str, plain: str) -> tuple:
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive(pw, salt)).encrypt(iv, plain.encode("utf-8"), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return b64(salt), b64(iv), b64(ct)


def render_markdown(md_text: str, title: str) -> str:
    """正本md → 読む専用のHTML。表は横スクロールできるよう包む。"""
    try:
        import markdown
    except ImportError:
        sys.exit("markdown が必要です: pip install markdown")
    body = markdown.markdown(md_text, extensions=["tables", "fenced_code", "sane_lists", "nl2br"])

    # 箇条書きの中にインデントして書かれたコードフェンスは python-markdown が拾えず、
    # 複数行のままインライン <code> になる（＝ブラウザで改行が潰れて1行に見える）。
    # 読める形にするため <pre><code> へ昇格し、ぶら下がりインデントを外す。
    langs = {"bash", "sh", "shell", "console", "python", "py", "js", "json", "yaml", "text", "md"}

    def promote(m):
        inner = m.group(1)
        if "\n" not in inner:
            return m.group(0)          # 本物のインラインcodeは触らない
        lines = inner.split("\n")
        if lines[0].strip().lower() in langs:
            # ```bash の言語指定が本文に落ちているので捨てて、全行を揃えて外す
            lines = lines[1:]
            pad = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
            lines = [l[pad:] for l in lines]
        else:
            # 1行目だけは markdown 側で既にインデントが外れている
            head, *rest = lines
            pad = min((len(l) - len(l.lstrip()) for l in rest if l.strip()), default=0)
            lines = [head] + [l[pad:] for l in rest]
        return "<pre><code>" + "\n".join(lines) + "</code></pre>"

    # <p> に包まれている場合は <p> ごと置き換え、それ以外（<li> の中など）は <code> だけ差し替える
    body = re.sub(r"<p>\s*<code>(.*?)</code>\s*</p>", promote, body, flags=re.S)
    body = re.sub(r"<code>(.*?)</code>", promote, body, flags=re.S)
    body = body.replace("<table>", '<div class="tw"><table>').replace("</table>", "</table></div>")
    return DOC_SHELL.replace("__TITLE__", title).replace("__BODY__", body)


def extract(pw: str) -> None:
    """リポジトリの暗号化ファイル → src/ に平文で展開"""
    os.makedirs(SRC, exist_ok=True)

    for name in PAGES:
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            print(f"  skip {name}（見つかりません）")
            continue
        m = PAYLOAD_RE.search(open(path, encoding="utf-8").read())
        if not m:
            sys.exit(f"{name}: 暗号ペイロードが見つかりません。ファイルが壊れている可能性があります。")
        salt, iv, ct, it = (base64.b64decode(m[1]), base64.b64decode(m[2]),
                            base64.b64decode(m[3]), int(m[4]))
        try:
            plain = AESGCM(derive(pw, salt)).decrypt(iv, ct, None).decode("utf-8")
        except Exception:
            sys.exit("復号に失敗しました。パスフレーズが違います。")
        open(os.path.join(SRC, name), "w", encoding="utf-8").write(plain)
        print(f"  {name:16s} → src/{name}  ({len(plain):,}字)")

    for enc_name, md_name in DOCS.items():
        path = os.path.join(ROOT, enc_name)
        if not os.path.exists(path):
            print(f"  skip {enc_name}（見つかりません）")
            continue
        d = json.load(open(path, encoding="utf-8"))
        salt, iv, ct = (base64.b64decode(d["s"]), base64.b64decode(d["i"]), base64.b64decode(d["c"]))
        try:
            plain = AESGCM(derive(pw, salt)).decrypt(iv, ct, None).decode("utf-8")
        except Exception:
            sys.exit(f"{enc_name}: 復号に失敗しました。パスフレーズが違います。")
        open(os.path.join(SRC, md_name), "w", encoding="utf-8").write(plain)
        print(f"  {enc_name:16s} → src/{md_name}  ({len(plain):,}字)")

    print(f"\n  ※ {', '.join(GENERATED)} は正本mdから自動生成されるため展開しません。")


def build(pw: str) -> None:
    """src/ の平文 → リポジトリ直下に暗号化して出力"""
    missing = [n for n in PAGES if not os.path.exists(os.path.join(SRC, n))]
    if missing:
        sys.exit(f"src/ に次のファイルがありません: {', '.join(missing)}\n"
                 f"先に `python3 crypt.py extract` を実行してください。")

    # 1) 正本md → profile.html を生成（手で編集させないため build のたびに作り直す）
    profile_md_path = os.path.join(SRC, PROFILE_MD)
    if os.path.exists(profile_md_path):
        md_text = open(profile_md_path, encoding="utf-8").read()
        html = render_markdown(md_text, TITLES["profile.html"])
        open(os.path.join(SRC, "profile.html"), "w", encoding="utf-8").write(html)
        print(f"  src/{PROFILE_MD} → src/profile.html を生成 ({len(html):,}字)")

    # 2) gate ページを暗号化
    for name in ALL_PAGES:
        src_path = os.path.join(SRC, name)
        if not os.path.exists(src_path):
            print(f"  skip {name}（src/ にありません）")
            continue
        plain = open(src_path, encoding="utf-8").read()
        s, i, c = seal(pw, plain)
        page = (GATE.replace("__TITLE__", TITLES[name])
                    .replace("__SALT__", s).replace("__IV__", i)
                    .replace("__CT__", c).replace("__ITER__", str(ITER)))
        assert plain[:200] not in page, f"{name}: 平文が出力に混入しています"
        open(os.path.join(ROOT, name), "w", encoding="utf-8").write(page)
        print(f"  src/{name:22s} → {name}  (元{len(plain):,}字 → {len(page):,}字)")

    # 3) ドキュメントを暗号化
    for enc_name, md_name in DOCS.items():
        src_path = os.path.join(SRC, md_name)
        if not os.path.exists(src_path):
            print(f"  skip {enc_name}（src/{md_name} がありません）")
            continue
        plain = open(src_path, encoding="utf-8").read()
        s, i, c = seal(pw, plain)
        blob = json.dumps({"v": 1, "n": ITER, "s": s, "i": i, "c": c}, ensure_ascii=False)
        assert plain[:200] not in blob, f"{enc_name}: 平文が出力に混入しています"
        open(os.path.join(ROOT, enc_name), "w", encoding="utf-8").write(blob + "\n")
        print(f"  src/{md_name:22s} → {enc_name}  (元{len(plain):,}字 → {len(blob):,}字)")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("extract", "build"):
        sys.exit(__doc__)
    mode = sys.argv[1]
    pw = get_password()
    print(f"\n[{mode}]")
    (extract if mode == "extract" else build)(pw)
    if mode == "build":
        print("\n完了。コミットしてよいのはリポジトリ直下の *.html と *.md.enc だけです"
              "（src/ は .gitignore 済み）。")
    else:
        print("\n完了。src/ を編集したあと `python3 crypt.py build` で暗号化し直してください。")


if __name__ == "__main__":
    main()
