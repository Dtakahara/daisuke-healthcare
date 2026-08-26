#!/usr/bin/env python3
"""
daisuke-healthcare サイトの暗号化／復号ツール

  python3 crypt.py extract   公開中の暗号化HTML（リポジトリ直下） → src/ に平文で展開
  python3 crypt.py build     src/ の平文HTML → リポジトリ直下に暗号化して出力

パスフレーズは環境変数 SITE_PW から取るか、なければ実行時に入力を求める。
コード・README・コミットには絶対に書かないこと。

暗号方式: PBKDF2-HMAC-SHA256（250,000回, 16byteソルト）で鍵導出 → AES-256-GCM（12byte IV）
"""
import os
import re
import sys
import base64
import hashlib
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
ITER = 250_000
PAGES = ["index.html", "routine.html", "dashboard.html", "bowl.html", "leucine.html"]

TITLES = {
    "index.html": "健康管理ハブ",
    "routine.html": "コンディショニングルーチン",
    "dashboard.html": "健康管理ダッシュボード",
    "bowl.html": "昼ボウルの栄養設計",
    "leucine.html": "ロイシン閾値と食事設計",
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


def get_password() -> str:
    pw = os.environ.get("SITE_PW") or getpass.getpass("パスフレーズ: ")
    if len(pw) < 16:
        sys.exit("パスフレーズが短すぎます。16文字以上・単語2つ以上にしてください。")
    return pw


def derive(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITER, 32)


def extract(pw: str) -> None:
    """リポジトリ直下の暗号化HTML → src/ に平文で展開"""
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


def build(pw: str) -> None:
    """src/ の平文HTML → リポジトリ直下に暗号化して出力"""
    missing = [n for n in PAGES if not os.path.exists(os.path.join(SRC, n))]
    if missing:
        sys.exit(f"src/ に次のファイルがありません: {', '.join(missing)}\n"
                 f"先に `python3 crypt.py extract` を実行してください。")
    for name in PAGES:
        plain = open(os.path.join(SRC, name), encoding="utf-8").read()
        salt, iv = os.urandom(16), os.urandom(12)
        ct = AESGCM(derive(pw, salt)).encrypt(iv, plain.encode("utf-8"), None)
        b64 = lambda b: base64.b64encode(b).decode()
        page = (GATE.replace("__TITLE__", TITLES[name])
                    .replace("__SALT__", b64(salt))
                    .replace("__IV__", b64(iv))
                    .replace("__CT__", b64(ct))
                    .replace("__ITER__", str(ITER)))
        # 事故防止: 平文が出力に混入していないことを確認
        assert plain[:200] not in page, f"{name}: 平文が出力に混入しています"
        open(os.path.join(ROOT, name), "w", encoding="utf-8").write(page)
        print(f"  src/{name:16s} → {name}  (元{len(plain):,}字 → {len(page):,}字)")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("extract", "build"):
        sys.exit(__doc__)
    mode = sys.argv[1]
    pw = get_password()
    print(f"\n[{mode}]")
    (extract if mode == "extract" else build)(pw)
    if mode == "build":
        print("\n完了。コミットしてよいのはリポジトリ直下のHTMLだけです（src/ は .gitignore 済み）。")
    else:
        print("\n完了。src/ を編集したあと `python3 crypt.py build` で暗号化し直してください。")


if __name__ == "__main__":
    main()
