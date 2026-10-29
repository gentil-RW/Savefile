"""LinkSaver website: paste a file link -> it streams to the visitor's device.
Nothing is stored on the server. Config via environment variables (see README)."""
import ipaddress, os, re, socket, time, urllib.parse
from collections import defaultdict, deque
import requests
from flask import Flask, Response, jsonify, render_template_string, request, stream_with_context

PUB = os.getenv("ADSENSE_PUB", "")          # e.g. ca-pub-1234567890123456
SLOT = os.getenv("ADSENSE_SLOT", "")        # ad unit slot id
SITE = os.getenv("SITE_NAME", "LinkSaver")
EMAIL = os.getenv("CONTACT_EMAIL", "you@example.com")
MAX_BYTES = int(os.getenv("MAX_MB", "500")) * 1048576
RATE = int(os.getenv("RATE_PER_MIN", "20"))
UA = {"User-Agent": "Mozilla/5.0 (compatible; LinkSaver)"}
app = Flask(__name__)
hits = defaultdict(deque)

def limited():
    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "?").split(",")[0].strip()
    q, now = hits[ip], time.time()
    while q and now - q[0] > 60: q.popleft()
    q.append(now)
    return len(q) > RATE

def check_url(url):
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname: raise ValueError("Enter a valid http(s) link")
    if u.port not in (None, 80, 443): raise ValueError("Port not allowed")
    for info in socket.getaddrinfo(u.hostname, u.port or 443):   # block internal addresses (SSRF)
        if not ipaddress.ip_address(info[4][0]).is_global: raise ValueError("Address not allowed")
    return url

def fetch(url):
    m = urllib.parse.urlparse(url)
    if m.netloc.endswith("dropbox.com"):
        url = urllib.parse.urlunparse(m._replace(query="dl=1"))
    for _ in range(5):                                          # follow redirects manually, re-checking each hop
        r = requests.get(check_url(url), stream=True, allow_redirects=False, timeout=(5, 20), headers=UA)
        if r.is_redirect and r.headers.get("Location"):
            url = urllib.parse.urljoin(url, r.headers["Location"]); r.close(); continue
        r.raise_for_status()
        return r, url
    raise ValueError("Too many redirects")

def filename(r, url):
    cd = r.headers.get("Content-Disposition", "")
    m = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", cd, re.I) or re.search(r'filename="?([^";]+)"?', cd, re.I)
    n = urllib.parse.unquote(m.group(1).strip()) if m else urllib.parse.unquote(urllib.parse.urlparse(url).path.split("/")[-1])
    n = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", n).strip(". ") or "download"
    return n

@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

@app.get("/api/info")
def info():
    if limited(): return jsonify(error="Too many requests, wait a minute"), 429
    try:
        r, url = fetch(request.args.get("url", "").strip())
        ctype = r.headers.get("Content-Type", "")
        size = int(r.headers.get("Content-Length") or 0)
        out = dict(name=filename(r, url), size=size, type=ctype.split(";")[0])
        r.close()
        if "text/html" in ctype: return jsonify(error="That link is a web page, not a downloadable file"), 400
        if size > MAX_BYTES: return jsonify(error=f"File too large (limit {MAX_BYTES // 1048576} MB)"), 413
        return jsonify(out)
    except Exception as e:
        return jsonify(error=str(e)[:150]), 400

@app.get("/dl")
def dl():
    if limited(): return "Too many requests", 429
    try:
        r, url = fetch(request.args.get("url", "").strip())
    except Exception as e:
        return str(e)[:150], 400
    if int(r.headers.get("Content-Length") or 0) > MAX_BYTES: return "File too large", 413
    def gen():
        sent = 0
        try:
            for chunk in r.iter_content(65536):
                sent += len(chunk)
                if sent > MAX_BYTES: break
                yield chunk
        finally: r.close()
    h = {"Content-Disposition": "attachment; filename*=UTF-8''" + urllib.parse.quote(filename(r, url))}
    if r.headers.get("Content-Length"): h["Content-Length"] = r.headers["Content-Length"]
    return Response(stream_with_context(gen()), headers=h, content_type="application/octet-stream")

@app.get("/ads.txt")
def ads(): return Response(f"google.com, {PUB.replace('ca-', '')}, DIRECT, f08c47fec0942fa0\n" if PUB else "", mimetype="text/plain")

@app.get("/healthz")
def health(): return "ok"

BASE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>{{site}} - Free file link downloader</title>
<meta name=description content="Paste a direct file link and download it to your device. Free, fast, no sign-up.">
{% if pub %}<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client={{pub}}" crossorigin=anonymous></script>{% endif %}
<style>:root{--bg:#fafaf8;--fg:#1a1a1a;--card:#fff;--ac:#c96442;--mut:#6b6b6b;--bd:#e2e2dc}
@media(prefers-color-scheme:dark){:root{--bg:#191917;--fg:#eee;--card:#262624;--mut:#a0a0a0;--bd:#3a3a36}}
*{box-sizing:border-box}body{margin:0;font:16px/1.6 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
.w{max-width:720px;margin:0 auto;padding:20px}header{display:flex;justify-content:space-between;align-items:center}
h1{font-size:2rem;margin:.6em 0 .2em}p.s{color:var(--mut);margin-top:0}
.box{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:16px;margin:16px 0}
input{width:100%;padding:14px;border-radius:10px;border:1px solid var(--bd);background:var(--bg);color:var(--fg);font:inherit}
.b{display:inline-block;margin-top:10px;padding:12px 20px;border:0;border-radius:10px;background:var(--ac);color:#fff;font:inherit;text-decoration:none;cursor:pointer}
.ad{min-height:100px;margin:16px 0;text-align:center;color:var(--mut);font-size:.8rem}
footer{border-top:1px solid var(--bd);margin-top:30px;padding-top:14px;color:var(--mut);font-size:.9rem}footer a{color:var(--mut);margin-right:14px}
#err{color:#c0392b}h2{font-size:1.2rem}</style></head><body><div class=w>
<header><b>{{site}}</b></header>{% block body %}{% endblock %}
<footer><a href=/>Home</a><a href=/privacy>Privacy</a><a href=/terms>Terms</a><a href="mailto:{{email}}">Contact</a></footer></div></body></html>"""

AD = """<div class=ad>{% if pub and slot %}<ins class=adsbygoogle style="display:block" data-ad-client="{{pub}}" data-ad-slot="{{slot}}" data-ad-format=auto data-full-width-responsive=true></ins>
<script>(adsbygoogle=window.adsbygoogle||[]).push({});</script>{% else %}Ad space{% endif %}</div>"""

HOME = BASE.replace("{% block body %}{% endblock %}", """
<h1>Download any file from a link</h1><p class=s>Paste a direct file link. We fetch it and save it to your device.</p>
<div class=box><input id=u type=url placeholder="https://example.com/file.zip" autocomplete=off>
<button class=b id=go>Get file</button><p id=err></p>
<div id=res hidden><h2 id=n></h2><p class=s id=m></p><a class=b id=d>Download</a></div></div>""" + AD + """
<h2>How it works</h2><p>Copy the direct link to a file (PDF, image, ZIP, audio, document...), paste it above and press <b>Get file</b>.
We check the link, show the file details, and stream it to your device. Files are never stored on our servers.</p>
<h2>Tips</h2><p>Links must point straight to a file. Pages that only <i>contain</i> files, or links that need a login, won't work.
Only download content you have the right to use.</p>""" + AD + """
<script>const $=i=>document.getElementById(i);
$('go').onclick=async()=>{const u=$('u').value.trim();$('err').textContent='';$('res').hidden=true;
if(!/^https?:\\/\\//i.test(u)){$('err').textContent='Paste a valid http(s) link';return}
$('go').textContent='Checking...';
try{const r=await fetch('/api/info?url='+encodeURIComponent(u));const j=await r.json();
if(!r.ok)throw new Error(j.error||'Failed');$('n').textContent=j.name;
$('m').textContent=(j.size?(j.size/1048576).toFixed(2)+' MB':'Unknown size')+' - '+(j.type||'file');
$('d').href='/dl?url='+encodeURIComponent(u);$('res').hidden=false}
catch(e){$('err').textContent=e.message}$('go').textContent='Get file'};
$('u').addEventListener('keydown',e=>{if(e.key==='Enter')$('go').click()});</script>""")

def page(tpl, **kw): return render_template_string(tpl, site=SITE, email=EMAIL, pub=PUB, slot=SLOT, **kw)
@app.get("/")
def home(): return page(HOME)

PRIV = BASE.replace("{% block body %}{% endblock %}", """<h1>Privacy Policy</h1>
<p>{{site}} does not store the files you download; they pass through our server to your device. We may log IP addresses and request times briefly for abuse prevention.</p>
<p>We use Google AdSense to show ads. Google and its partners use cookies to serve ads based on your visits to this and other sites. You can opt out of personalized advertising at <a href="https://adssettings.google.com">adssettings.google.com</a>. See <a href="https://policies.google.com/technologies/ads">how Google uses data</a>.</p>
<p>Contact: {{email}}</p>""")
TERMS = BASE.replace("{% block body %}{% endblock %}", """<h1>Terms of Use</h1>
<p>You may use {{site}} only to download files you are legally allowed to access. Do not use it to infringe copyright, bypass access controls, or abuse the service. We may block links or users at any time. The service is provided as is, without warranty.</p>
<p>Copyright or abuse reports: {{email}}</p>""")
@app.get("/privacy")
def privacy(): return page(PRIV)
@app.get("/terms")
def terms(): return page(TERMS)

if __name__ == "__main__": app.run(port=8000, debug=False)
