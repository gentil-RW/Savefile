"""LinkSaver v2: paste a file link -> streams to the visitor's device (nothing stored).
Hardened for public hosting: SSRF-safe connections, quotas, concurrency cap, abuse blocklist,
consent-gated ads, and content pages for AdSense. Config via env vars (see README)."""
import ipaddress, os, re, socket, subprocess, tempfile, threading, time, urllib.parse
from collections import defaultdict, deque
import requests, urllib3.util.connection as uc
from flask import Flask, Response, abort, jsonify, render_template_string, request, stream_with_context
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from PIL import Image

env = os.getenv
PUB, SLOT = env("ADSENSE_PUB", ""), env("ADSENSE_SLOT", "")
SITE, EMAIL = env("SITE_NAME", "LinkSaver"), env("CONTACT_EMAIL", "you@example.com")
MAX_BYTES = int(env("MAX_MB", "200")) * 1048576          # per file
DAILY_BYTES = int(env("DAILY_MB", "1000")) * 1048576     # per visitor per day
RATE = int(env("RATE_PER_MIN", "20"))
STREAMS = threading.BoundedSemaphore(int(env("MAX_STREAMS", "20")))
BLOCKED = {d.strip().lower() for d in (env("BLOCKED_DOMAINS", "") +
    ",youtube.com,youtu.be,netflix.com,primevideo.com,disneyplus.com,hbomax.com,spotify.com").split(",") if d.strip()}
UA = {"User-Agent": "Mozilla/5.0 (compatible; LinkSaver)"}
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=int(env("PROXY_HOPS", "1")))
hits, usage = defaultdict(deque), {}

# --- SSRF defence: validate the IP actually connected to (stops DNS rebinding) ---
_orig = uc.create_connection
def _safe_cc(address, *a, **k):
    host, port = address
    ips = [i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    if not ips or not all(ipaddress.ip_address(i).is_global for i in ips): raise OSError("Address not allowed")
    return _orig((ips[0], port), *a, **k)
uc.create_connection = _safe_cc

def msg(e): return "Could not fetch this link" if isinstance(e, (requests.RequestException, OSError)) else str(e)[:150]
def day(): return time.strftime("%Y%m%d")
def used(ip): d, b = usage.get(ip, (day(), 0)); return b if d == day() else 0
def limited():
    q, now = hits[request.remote_addr], time.time()
    while q and now - q[0] > 60: q.popleft()
    q.append(now); return len(q) > RATE

def check_url(url):
    u = urllib.parse.urlparse(url); h = (u.hostname or "").lower()
    if u.scheme not in ("http", "https") or not h: raise ValueError("Enter a valid http(s) link")
    if u.port not in (None, 80, 443): raise ValueError("Port not allowed")
    try: ipaddress.ip_address(h); raise ValueError("Links using raw IP addresses are not allowed")
    except ValueError as e:
        if "raw IP" in str(e): raise
    if any(h == d or h.endswith("." + d) for d in BLOCKED): raise ValueError("This site is not supported")
    return url

VIDEO_FMT = {"MPEG4", "h.264", "h.264 IA", "512Kb MPEG4", "Ogg Video", "WebM"}
def resolve(url):
    """Turn Internet Archive / Wikimedia Commons page links into direct file links."""
    u = urllib.parse.urlparse(url); h = (u.hostname or "").lower()
    try:
        if h in ("archive.org", "www.archive.org") and u.path.startswith("/details/"):
            ident = u.path.split("/")[2]
            j = requests.get("https://archive.org/metadata/" + urllib.parse.quote(ident), timeout=15, headers=UA).json()
            vids = [f for f in j.get("files", []) if f.get("format") in VIDEO_FMT]
            if vids:
                f = max(vids, key=lambda f: int(f.get("size") or 0))
                return f"https://archive.org/download/{urllib.parse.quote(ident)}/{urllib.parse.quote(f['name'])}"
        if h == "commons.wikimedia.org" and u.path.startswith("/wiki/File:"):
            j = requests.get("https://commons.wikimedia.org/w/api.php", timeout=15, headers=UA, params={
                "action": "query", "format": "json", "prop": "imageinfo", "iiprop": "url",
                "titles": urllib.parse.unquote(u.path[len("/wiki/"):])}).json()
            return next(iter(j["query"]["pages"].values()))["imageinfo"][0]["url"]
    except Exception: pass
    return url

def fetch(url):
    url = resolve(url)
    m = urllib.parse.urlparse(url)
    if m.netloc.endswith("dropbox.com"): url = urllib.parse.urlunparse(m._replace(query="dl=1"))
    for _ in range(5):
        r = requests.get(check_url(url), stream=True, allow_redirects=False, timeout=(5, 20), headers=UA)
        if r.is_redirect and r.headers.get("Location"):
            url = urllib.parse.urljoin(url, r.headers["Location"]); r.close(); continue
        r.raise_for_status(); return r, url
    raise ValueError("Too many redirects")

def filename(r, url):
    cd = r.headers.get("Content-Disposition", "")
    m = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", cd, re.I) or re.search(r'filename="?([^";]+)"?', cd, re.I)
    n = urllib.parse.unquote(m.group(1).strip()) if m else urllib.parse.unquote(urllib.parse.urlparse(url).path.split("/")[-1])
    return re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", n).strip(". ") or "download"

def verdict(r):
    size = int(r.headers.get("Content-Length") or 0)
    if size > MAX_BYTES: return f"File too large (limit {MAX_BYTES // 1048576} MB)", 413
    if used(request.remote_addr) + size > DAILY_BYTES: return "Daily download limit reached. Try again tomorrow", 429
    return None, 200

@app.after_request
def sec(resp):
    resp.headers.update({"X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin"}); return resp

@app.get("/api/info")
def info():
    if limited(): return jsonify(error="Too many requests, wait a minute"), 429
    try:
        r, url = fetch(request.args.get("url", "").strip()); err, code = verdict(r)
        out = dict(name=filename(r, url), size=int(r.headers.get("Content-Length") or 0), type=r.headers.get("Content-Type", "").split(";")[0])
        r.close(); return (jsonify(error=err), code) if err else jsonify(out)
    except Exception as e: return jsonify(error=msg(e)), 400

@app.get("/dl")
def dl():
    if limited(): return "Too many requests", 429
    if request.args.get("ok") != "1": return "Please confirm you have the right to download this file", 400
    try: r, url = fetch(request.args.get("url", "").strip())
    except Exception as e: return msg(e), 400
    err, code = verdict(r)
    if err: r.close(); return err, code
    if not STREAMS.acquire(blocking=False): r.close(); return "Server busy, please retry in a minute", 503
    ip = request.remote_addr
    def gen():
        sent = 0
        try:
            for c in r.iter_content(65536):
                sent += len(c)
                if sent > MAX_BYTES: break
                yield c
        finally:
            r.close(); STREAMS.release(); usage[ip] = (day(), used(ip) + sent)
    h = {"Content-Disposition": "attachment; filename*=UTF-8''" + urllib.parse.quote(filename(r, url))}
    if r.headers.get("Content-Length"): h["Content-Length"] = r.headers["Content-Length"]
    return Response(stream_with_context(gen()), headers=h, content_type="application/octet-stream")

# --- file converter (images via Pillow, audio/video via ffmpeg) ---
CONVERT_MB = int(env("CONVERT_MB", "50")); CONV_TIMEOUT = int(env("CONVERT_TIMEOUT", "100"))
CONV = threading.BoundedSemaphore(int(env("MAX_CONVERT", "1")))
app.config["MAX_CONTENT_LENGTH"] = (CONVERT_MB + 1) * 1048576
Image.MAX_IMAGE_PIXELS = 50_000_000
IMG_IN = {"jpg", "jpeg", "png", "webp", "gif", "bmp", "tif", "tiff"}
AUD_IN = {"mp3", "wav", "ogg", "m4a", "aac", "flac", "opus", "wma"}
VID_IN = {"mp4", "mov", "mkv", "webm", "avi", "m4v", "3gp"}
IMG_OUT = {"jpg": "JPEG", "png": "PNG", "webp": "WEBP", "gif": "GIF", "bmp": "BMP", "tiff": "TIFF", "pdf": "PDF"}
AUD_OUT = {"mp3": ["-c:a", "libmp3lame", "-q:a", "2"], "wav": [], "ogg": ["-c:a", "libvorbis"],
           "m4a": ["-c:a", "aac", "-b:a", "192k"], "flac": []}
VID_OUT = {"mp4": ["-c:v", "libx264", "-preset", "veryfast", "-crf", "28", "-c:a", "aac", "-movflags", "+faststart", "-vf", "scale=min(1280\\,iw):-2"],
           "webm": ["-c:v", "libvpx", "-deadline", "realtime", "-cpu-used", "8", "-b:v", "1M", "-c:a", "libvorbis"],
           "gif": ["-vf", "fps=12,scale=480:-1:flags=lanczos", "-an"]}
TYPES = {"image": {"in": sorted(IMG_IN), "out": list(IMG_OUT)}, "audio": {"in": sorted(AUD_IN), "out": list(AUD_OUT)},
         "video": {"in": sorted(VID_IN), "out": list(VID_OUT) + list(AUD_OUT)}}

def conv_image(src, dst, fmt):
    im = Image.open(src)
    if fmt in ("jpg", "pdf", "bmp"):
        if im.mode in ("RGBA", "LA", "P"):
            im = im.convert("RGBA"); bg = Image.new("RGB", im.size, "white"); bg.paste(im, mask=im.split()[-1]); im = bg
        elif im.mode != "RGB": im = im.convert("RGB")
    im.save(dst, IMG_OUT[fmt], **({"quality": 90} if fmt in ("jpg", "webp") else {}))

def conv_ffmpeg(src, dst, fmt):
    audio = fmt in AUD_OUT
    cmd = ["ffmpeg", "-nostdin", "-y", "-i", src, "-t", "900", *(["-vn"] if audio else []), *(AUD_OUT[fmt] if audio else VID_OUT[fmt]), dst]
    subprocess.run(cmd, capture_output=True, timeout=CONV_TIMEOUT, check=True)

@app.post("/api/convert")
def convert():
    if limited(): return "Too many requests, wait a minute", 429
    f, fmt = request.files.get("file"), (request.form.get("to") or "").lower()
    if not f or not f.filename: return "Choose a file", 400
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    cat = "image" if ext in IMG_IN else "audio" if ext in AUD_IN else "video" if ext in VID_IN else None
    if not cat or fmt not in TYPES[cat]["out"] or fmt == ext: return "That conversion is not supported", 400
    ip = request.remote_addr
    if used(ip) >= DAILY_BYTES: return "Daily limit reached. Try again tomorrow", 429
    if not CONV.acquire(blocking=False): return "Converter is busy, try again in a minute", 503
    try:
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, "in." + ext), os.path.join(d, "out." + fmt)
            f.save(src); size = os.path.getsize(src)
            conv_image(src, dst, fmt) if cat == "image" else conv_ffmpeg(src, dst, fmt)
            data = open(dst, "rb").read()
        usage[ip] = (day(), used(ip) + size + len(data))
    except subprocess.TimeoutExpired: return "Conversion took too long. Try a smaller file", 504
    except Exception: return "Could not convert this file", 422
    finally: CONV.release()
    name = (secure_filename(f.filename.rsplit(".", 1)[0]) or "file") + "." + fmt
    return Response(data, headers={"Content-Disposition": "attachment; filename*=UTF-8''" + urllib.parse.quote(name)},
                    content_type="application/octet-stream")

# --- templates ---
BASE = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{{title}}</title><meta name=description content="{{desc}}">
<style>:root{--bg:#fafaf8;--fg:#1a1a1a;--card:#fff;--ac:#c96442;--mut:#6b6b6b;--bd:#e2e2dc}
@media(prefers-color-scheme:dark){:root{--bg:#191917;--fg:#eee;--card:#262624;--mut:#a0a0a0;--bd:#3a3a36}}
*{box-sizing:border-box}body{margin:0;font:16px/1.6 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
.w{max-width:720px;margin:0 auto;padding:20px}a{color:var(--ac)}h1{font-size:2rem;margin:.6em 0 .2em}h2{font-size:1.2rem;margin-top:1.4em}
.s{color:var(--mut)}.box{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:16px;margin:16px 0}
input[type=url]{width:100%;padding:14px;border-radius:10px;border:1px solid var(--bd);background:var(--bg);color:var(--fg);font:inherit}
.b{display:inline-block;margin-top:10px;padding:12px 20px;border:0;border-radius:10px;background:var(--ac);color:#fff;font:inherit;text-decoration:none;cursor:pointer}
.ad{min-height:100px;margin:16px 0;text-align:center;color:var(--mut);font-size:.8rem}
footer{border-top:1px solid var(--bd);margin-top:30px;padding-top:14px;font-size:.9rem}footer a{color:var(--mut);margin-right:14px}
#err{color:#c0392b}#cb{position:fixed;left:0;right:0;bottom:0;background:var(--card);border-top:1px solid var(--bd);padding:14px;display:none;font-size:.9rem}
#cb .b{margin:6px 6px 0 0;padding:8px 14px}.in{max-width:720px;margin:0 auto;padding:0 20px}
.hd{background:#0f1520;padding:14px 0}.hd .in{display:flex;justify-content:space-between;align-items:center}
.hd b{font-size:1.25rem;color:#ffe14d}.hd a{color:#fff;text-decoration:none;margin-left:14px;font-size:.9rem}
.hero{background:linear-gradient(160deg,#0b86c9,#0a56b0);color:#fff;padding:28px 0 34px;text-align:center}
.hero h1{font-size:1.9rem;margin:.2em 0}.hero p{margin:.3em 0 1em}
.sbar{display:flex;flex-wrap:wrap;gap:8px;background:#fff;border-radius:14px;padding:8px;align-items:center}
.sbar input{flex:1 1 170px;min-width:0;border:0!important;background:#fff!important;color:#111!important}
.sbar #x{border:0;background:none;font-size:1.7rem;color:#888;cursor:pointer;padding:0 6px}
.sbar .go{margin:0;background:#12b24a;padding:14px 24px;font-weight:700}
.ck{display:block;margin-top:10px;font-size:.85rem;text-align:left}.ck a{color:#fff}.hero #err{color:#ffd1cc}
.card{background:var(--card);color:var(--fg);border-radius:14px;padding:14px;margin-top:14px;text-align:left}
.card .row{display:flex;align-items:center;gap:10px;justify-content:space-between;border-top:1px solid var(--bd);padding:10px 0}
.tag{background:#ffb02e;color:#222;border-radius:6px;padding:2px 8px;font-size:.75rem;font-weight:700}
.dlb{background:#12b24a;margin:0}.alt{background:transparent;border:1px solid #12b24a;color:#12b24a;margin:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px}.tile b{display:block}
.steps div{display:flex;gap:12px;margin:12px 0}.steps i{flex:0 0 32px;height:32px;border-radius:50%;background:#12b24a;color:#fff;font-style:normal;text-align:center;line-height:32px;font-weight:700}
details{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:12px 14px;margin:10px 0}summary{cursor:pointer;font-weight:600}
.ft{background:#0f1520;color:#cbd5e1;margin-top:40px;padding:24px 0;border:0}.ft a{color:#cbd5e1}
</style></head><body><header class=hd><div class=in><b>{{site}}</b><span><a href=/convert>Convert</a><a href=/videos>Videos</a><a href=/articles>Articles</a></span></div></header>{{body|safe}}
<footer class=ft><div class=in><a href=/>Home</a><a href=/convert>Convert</a><a href=/articles>Articles</a><a href=/videos>Videos</a><a href=/guide>Guide</a><a href=/faq>FAQ</a><a href=/about>About</a><a href=/privacy>Privacy</a><a href=/terms>Terms</a><a href=/dmca>Copyright</a><p>&copy; {{site}}</p></div></footer>
<div id=cb>We use cookies for ads (Google AdSense). Personalized ads need your consent.<br>
<button class=b onclick="setC('all')">Accept all</button><button class=b style="background:#777" onclick="setC('min')">Non-personalized only</button></div>
<script>
const PUB="{{pub}}";function initAds(m){if(!PUB)return;
if(m==='min'){window.adsbygoogle=window.adsbygoogle||[];window.adsbygoogle.requestNonPersonalizedAds=1}
const s=document.createElement('script');s.async=true;s.crossOrigin='anonymous';
s.src='https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client='+PUB;
s.onload=()=>document.querySelectorAll('ins.adsbygoogle').forEach(()=>{try{(adsbygoogle=window.adsbygoogle||[]).push({})}catch(e){}});
document.head.appendChild(s)}
function setC(m){try{localStorage.setItem('consent',m)}catch(e){}document.getElementById('cb').style.display='none';initAds(m)}
(function(){let m=null;try{m=localStorage.getItem('consent')}catch(e){}
if(m)initAds(m);else if(PUB)document.getElementById('cb').style.display='block'})();
</script></body></html>"""

AD = """<div class=ad>{% if pub and slot %}<ins class=adsbygoogle style="display:block" data-ad-client="{{pub}}" data-ad-slot="{{slot}}" data-ad-format=auto data-full-width-responsive=true></ins>{% else %}Ad space{% endif %}</div>"""

HOME = """<section class=hero><div class=in><h1>Free File &amp; Video Link Downloader</h1>
<p>Paste a link and save the file to your device in seconds. Works with direct links, Internet Archive, Wikimedia Commons, Dropbox and Google Drive.</p>
<div class=sbar><input id=u type=url placeholder="Paste your link here" autocomplete=off><button id=x aria-label=Clear>&times;</button><button class="b go" id=go>Download</button></div>
<label class=ck><input type=checkbox id=ok> I have the right to download this file and agree to the <a href=/terms>Terms</a>.</label>
<p id=err></p>
<div class=card id=res hidden><b id=n></b><div class=s id=m></div>
<div class=row><span class=tag>SAVE</span><span>Download to your device</span><a class="b dlb" id=d>Save file</a></div>
<div class=row><span class=tag>CONVERT</span><span>Change the format</span><a class="b alt" href=/convert>Open converter</a></div></div>
</div></section><div class=w>""" + AD + """
<h2>Why people use {{site}}</h2><div class=grid>
<div class=tile><b>Instant link check</b><span class=s>See the file name and size before you download.</span></div>
<div class=tile><b>Works on any device</b><span class=s>Phone, tablet or computer. Nothing to install.</span></div>
<div class=tile><b>Private by design</b><span class=s>Files stream straight to you and are never stored.</span></div>
<div class=tile><b>Built-in converter</b><span class=s>Change images, audio and video to other formats.</span></div></div>
<h2>How it works</h2><div class=steps>
<div><i>1</i><span><b>Copy the link</b><br><span class=s>Copy the address of the file or video page.</span></span></div>
<div><i>2</i><span><b>Paste and check</b><br><span class=s>Paste it above, tick the box and press Download.</span></span></div>
<div><i>3</i><span><b>Save it</b><br><span class=s>Tap Save file. Find it in your Downloads folder.</span></span></div></div>
<h2>Supported sources</h2><div class=grid>
<div class=tile><b>Direct links</b><span class=s>PDF, ZIP, MP3, MP4, images</span></div>
<div class=tile><b>Internet Archive</b><span class=s>Public-domain video and audio</span></div>
<div class=tile><b>Wikimedia Commons</b><span class=s>Freely licensed media</span></div>
<div class=tile><b>Dropbox</b><span class=s>Public share links</span></div>
<div class=tile><b>Google Drive</b><span class=s>Anyone-with-link files</span></div>
<div class=tile><b>File converter</b><span class=s><a href=/convert>Open the converter</a></span></div></div>
""" + AD + """
<h2>FAQ</h2>
<details><summary>Do I need to install anything?</summary><p>No. It works in your browser on any device.</p></details>
<details><summary>What formats can I download?</summary><p>Any file a link points to: documents, images, music, video, archives and more. Use the <a href=/convert>converter</a> to change formats.</p></details>
<details><summary>Does it have ads?</summary><p>Yes, a few. They keep the service free.</p></details>
<details><summary>Can I save videos for offline watching?</summary><p>Yes, when the video is yours or freely licensed. See <a href=/videos>free videos you can download legally</a>.</p></details>
<details><summary>Why are some sites not supported?</summary><p>We do not support platforms whose rules forbid downloading, so we stay within copyright rules. Read the <a href=/faq>full FAQ</a>.</p></details>
<script>const $=i=>document.getElementById(i);
$('x').onclick=()=>{$('u').value='';$('res').hidden=true;$('err').textContent='';$('u').focus()};
$('go').onclick=async()=>{const u=$('u').value.trim();$('err').textContent='';$('res').hidden=true;
if(!/^https?:\\/\\//i.test(u)){$('err').textContent='Paste a valid http(s) link';return}
if(!$('ok').checked){$('err').textContent='Please tick the confirmation box';return}
$('go').textContent='Checking...';
try{const r=await fetch('/api/info?url='+encodeURIComponent(u));const j=await r.json();
if(!r.ok)throw new Error(j.error||'Failed');$('n').textContent=j.name;
$('m').textContent=(j.size?(j.size/1048576).toFixed(2)+' MB':'Unknown size')+' - '+(j.type||'file');
$('d').href='/dl?ok=1&url='+encodeURIComponent(u);$('res').hidden=false}
catch(e){$('err').textContent=e.message}$('go').textContent='Download'};
$('u').addEventListener('keydown',e=>{if(e.key==='Enter')$('go').click()});</script></div>"""

CONVERT = """<h1>Free file converter</h1><p class=s>Convert images, audio and video to another format. Files are deleted right after conversion.</p>
<div class=box><input id=f type=file style="width:100%;padding:10px">
<p id=info class=s>Choose a file (up to {{mb}} MB).</p>
<select id=to style="width:100%;padding:12px;font:inherit;border-radius:10px" disabled></select>
<button class=b id=go disabled>Convert</button><p id=err></p><a class=b id=sv hidden>Save converted file</a></div>""" + AD + """
<h2>Supported formats</h2><p><b>Images:</b> JPG, PNG, WebP, GIF, BMP, TIFF, PDF.<br><b>Audio:</b> MP3, WAV, OGG, M4A, FLAC.<br>
<b>Video:</b> MP4, WebM, GIF, or extract the sound as MP3, WAV, OGG, M4A or FLAC. Only convert files you have the right to use.</p>
<script id=t type=application/json>{{ T|tojson }}</script>
<script>const $=i=>document.getElementById(i),T=JSON.parse($('t').textContent);let cat=null;
$('f').onchange=()=>{const f=$('f').files[0];$('sv').hidden=true;$('err').textContent='';if(!f)return;
const ext=f.name.split('.').pop().toLowerCase();cat=Object.keys(T).find(k=>T[k].in.includes(ext));
if(!cat){$('err').textContent='This file type is not supported';$('go').disabled=true;$('to').disabled=true;return}
$('to').innerHTML=T[cat].out.filter(x=>x!==ext).map(x=>'<option value='+x+'>Convert to '+x.toUpperCase()+'</option>').join('');
$('to').disabled=false;$('go').disabled=false;$('info').textContent=f.name+' ('+(f.size/1048576).toFixed(1)+' MB)'};
$('go').onclick=async()=>{const f=$('f').files[0];if(!f)return;$('err').textContent='';$('sv').hidden=true;
$('go').disabled=true;$('go').textContent='Converting... please wait';
const fd=new FormData();fd.append('file',f);fd.append('to',$('to').value);
try{const r=await fetch('/api/convert',{method:'POST',body:fd});if(!r.ok)throw new Error(await r.text());
const b=await r.blob(),a=$('sv');a.href=URL.createObjectURL(b);a.download=f.name.replace(/\\.[^.]+$/,'')+'.'+$('to').value;a.hidden=false}
catch(e){$('err').textContent=(e.message||'Failed').slice(0,150)}
$('go').disabled=false;$('go').textContent='Convert'};</script>"""

PAGES = {
"guide": ("How to find a direct download link", """<h1>How to find a direct download link</h1>
<p>A direct link points straight at a file, not at a page about it. You can usually tell by the ending: .pdf, .zip, .mp3, .jpg, .docx and similar.</p>
<h2>Right-click method</h2><p>On a computer, right-click a download button or file name and choose <b>Copy link address</b>. On a phone, press and hold the link and pick <b>Copy link</b>.</p>
<h2>Cloud storage links</h2><p>Dropbox share links work directly. For Google Drive, make sure sharing is set to "Anyone with the link" before copying it.</p>
<h2>When a link does not work</h2><p>Links that ask you to sign in or expire after a short time cannot be fetched. Web page links are saved as an HTML file. If the owner removed the file, you will see an error.</p>"""),
"videos": ("Download free videos legally", """<h1>Download free videos legally</h1>
<p>You can save videos with {{site}} when the owner allows it. Paste a direct video link (ending in .mp4, .webm or .mov), or the page link of a video on one of these sources:</p>
<h2>Internet Archive</h2><p>A huge library of public-domain films, old TV, classic cartoons, lectures and community uploads. Open a video page on archive.org, copy the address, and paste it here. Check each item's license on its page.</p>
<h2>Wikimedia Commons</h2><p>Freely licensed videos used on Wikipedia. Open the file page, copy the address and paste it here. Credit the author if the license asks for it.</p>
<h2>Your own videos</h2><p>Videos you uploaded to a cloud drive can be shared with "Anyone with the link" and saved here. YouTube Studio also lets you download your own uploads.</p>
<h2>Before you download</h2><p>Always check the license. Public domain and Creative Commons videos are usually fine to keep and share; commercial films, TV shows and most platform videos are not. See our <a href=/dmca>copyright policy</a>.</p>"""),
"articles": ("Articles", """<h1>Articles</h1>
<p><a href=/public-domain-movies>Where to find free public-domain movies</a></p>
<p><a href=/creative-commons-videos>How to find Creative Commons videos you can reuse</a></p>
<p><a href=/direct-link-vs-page-link>Direct link or page link: what is the difference?</a></p>
<p><a href=/download-safely>How to download files safely</a></p>"""),
"public-domain-movies": ("Where to find free public-domain movies", """<h1>Where to find free public-domain movies</h1>
<p>A film is in the public domain when its copyright has expired or never applied, which means anyone may watch, keep and share it. The rules differ from country to country, so a film that is free in one place may still be protected in another. Always read the notes on the page you download from.</p>
<h2>Start with the Internet Archive</h2><p>The Internet Archive runs a large moving-image library with silent films, classic cartoons, old newsreels, educational films and lectures. Each item has a description and usually a rights note. Paste the item's page link into {{site}} and we find the video file for you.</p>
<h2>Try national and university archives</h2><p>Many libraries and film archives publish digitised collections that are free to use. Look for a "rights" or "reuse" section on each collection and follow what it says.</p>
<h2>Check before you share</h2><p>A new restoration, soundtrack or edit of an old film can have its own copyright. If you plan to post or sell a video, confirm the exact version you downloaded is free to reuse.</p>"""),
"creative-commons-videos": ("How to find Creative Commons videos you can reuse", """<h1>How to find Creative Commons videos you can reuse</h1>
<p>Creative Commons licenses let creators say in advance how others may use their work. Knowing the main types saves you from mistakes.</p>
<h2>The common licenses</h2><p><b>CC0</b> means no rights reserved; use it freely. <b>CC BY</b> lets you reuse the video if you credit the author. <b>CC BY-SA</b> adds that anything you make from it must use the same license. <b>NC</b> means non-commercial use only, and <b>ND</b> means you may not change the work.</p>
<h2>Where to look</h2><p>Wikimedia Commons hosts many freely licensed videos, and every file page lists its license and author. Paste a file page link into {{site}} to save the video.</p>
<h2>Give credit properly</h2><p>When a license asks for credit, note the title, the author, the source link and the license name. Keeping a short text file with these details next to the video makes it easy later.</p>"""),
"direct-link-vs-page-link": ("Direct link or page link: what is the difference?", """<h1>Direct link or page link: what is the difference?</h1>
<p>A <b>page link</b> opens a web page that talks about a file, often with buttons, previews and ads. A <b>direct link</b> goes straight to the file itself, and your phone or computer starts downloading it.</p>
<h2>How to tell them apart</h2><p>Direct links usually end with a file type such as .pdf, .zip, .mp3 or .mp4. Page links usually end with a page name or a long code. If tapping the link shows a page first, it is a page link.</p>
<h2>How to get a direct link</h2><p>Press and hold the download button or the file name on a phone, then choose Copy link. On a computer, right-click and choose Copy link address. Paste it into {{site}} and we will check it before you download.</p>
<h2>When it fails</h2><p>Links that need a sign-in, or that stop working after a short time, cannot be saved by any downloader. Ask the owner for a public link instead.</p>"""),
"download-safely": ("How to download files safely", """<h1>How to download files safely</h1>
<p>Most downloads are harmless, but a few simple habits keep your device safe.</p>
<h2>Check the source</h2><p>Download only from sites you trust, and be careful with links sent by strangers in messages or comments.</p>
<h2>Look at the file type</h2><p>Documents, images, music and video are low risk. Be careful with programs and installers (.exe, .apk, .msi, .bat). A "video" that ends in .exe is not a video.</p>
<h2>Check the size</h2><p>If a short song is several hundred megabytes, or a large movie is only a few kilobytes, something is wrong.</p>
<h2>Scan and update</h2><p>Keep your phone or computer updated and run a security scan on files you are unsure about. If something looks wrong, delete it without opening it.</p>"""),
"faq": ("FAQ", """<h1>Frequently asked questions</h1>
<h2>Is it free?</h2><p>Yes. The site is supported by advertising.</p>
<h2>Do you keep my files?</h2><p>No. Files stream through our server to your device and are not stored.</p>
<h2>Why was my link rejected?</h2><p>It may need a login, exceed the size limit, or come from a site we do not support.</p>
<h2>Is there a size or daily limit?</h2><p>Yes, to keep the service available for everyone. The limits are shown in the error message when reached.</p>
<h2>Can I download copyrighted material?</h2><p>Only if you have permission. See our <a href=/terms>Terms</a> and <a href=/dmca>copyright policy</a>.</p>"""),
"about": ("About", """<h1>About {{site}}</h1><p>{{site}} is a simple tool that saves a file from a direct link onto your own device, with no sign-up and no software to install.
We keep it fast and safe by checking every link, limiting abuse, and never storing your files.</p><p>Questions: <a href="mailto:{{email}}">{{email}}</a></p>"""),
"privacy": ("Privacy Policy", """<h1>Privacy Policy</h1><p>{{site}} does not store the files you download. Our server may briefly log your IP address and request times to prevent abuse.</p>
<p>We use Google AdSense. Google and partners use cookies to serve ads based on your visits to this and other sites. With your consent, ads may be personalized; otherwise only non-personalized ads are shown. You can manage ad settings at <a href="https://adssettings.google.com">adssettings.google.com</a> and learn more at <a href="https://policies.google.com/technologies/ads">Google's advertising page</a>. Your consent choice is stored in your browser.</p><p>Contact: {{email}}</p>"""),
"terms": ("Terms of Use", """<h1>Terms of Use</h1><p>You may use {{site}} only for files you are legally allowed to access and copy. You must not use it to infringe copyright, bypass paywalls or access controls, distribute malware, or overload the service.
We may block links or visitors at any time. The service is provided as is, without warranty, and you are responsible for what you download.</p>"""),
"dmca": ("Copyright policy", """<h1>Copyright and takedown policy</h1><p>We respect intellectual property. We do not host files; links are fetched on request. If you believe a link on a specific site is infringing, email <a href="mailto:{{email}}">{{email}}</a> with the URL of the work, the infringing link, your contact details, and a statement that you are the owner or authorized to act for the owner.
We will block the reported site or link promptly and may terminate repeat abusers.</p>"""),
}

def render(title, body, desc="", wide=False, **kw):
    body = render_template_string(body, site=SITE, email=EMAIL, pub=PUB, slot=SLOT, **kw)
    if not wide: body = "<div class=w>" + body + "</div>"
    return render_template_string(BASE, title=f"{title} - {SITE}", desc=desc or title, body=body, site=SITE, pub=PUB)

@app.get("/")
def home(): return render("Free file link downloader", HOME, "Paste a direct file link and save it to your device. Free, fast, no sign-up.", wide=True)
@app.get("/convert")
def convert_page(): return render("Free file converter", CONVERT, "Convert images, audio and video between popular formats for free.", T=TYPES, mb=CONVERT_MB)
@app.get("/<slug>")
def page(slug):
    if slug not in PAGES: abort(404)
    return render(PAGES[slug][0], PAGES[slug][1])
@app.get("/ads.txt")
def ads(): return Response(f"google.com, {PUB.replace('ca-', '')}, DIRECT, f08c47fec0942fa0\n" if PUB else "", mimetype="text/plain")
@app.get("/robots.txt")
def robots(): return Response(f"User-agent: *\nDisallow: /dl\nDisallow: /api/\nSitemap: {request.url_root}sitemap.xml\n", mimetype="text/plain")
@app.get("/sitemap.xml")
def sitemap():
    u = "".join(f"<url><loc>{request.url_root}{s}</loc></url>" for s in ["", "convert", *PAGES])
    return Response(f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{u}</urlset>', mimetype="application/xml")
@app.get("/healthz")
def health(): return "ok"

if __name__ == "__main__": app.run(port=8000)
