# LinkSaver website

Paste a direct file link -> streams to the visitor's device. Nothing stored on the server.

## Run locally
    pip install -r requirements.txt && python app.py     # http://127.0.0.1:8000

## Deploy online (any Docker host: Render, Railway, Fly.io, a VPS)
1. Push this folder to a GitHub repo, create a new "Web Service" from it (Dockerfile is detected).
2. Set environment variables:
   - SITE_NAME      your brand name
   - CONTACT_EMAIL  shown on Privacy/Terms pages
   - ADSENSE_PUB    ca-pub-XXXXXXXXXXXXXXXX  (after AdSense gives you this)
   - ADSENSE_SLOT   ad unit id (create a "Display ad" unit in AdSense)
   - MAX_MB (default 500), RATE_PER_MIN (default 20)
3. Attach your own domain and enable HTTPS (AdSense requires your own domain).

## AdSense checklist
- Apply at adsense.google.com with your domain; /ads.txt is served automatically once ADSENSE_PUB is set.
- Privacy and Terms pages are included (AdSense requires a privacy policy).
- If you have EU/UK visitors you need a cookie-consent banner (use Google's free Funding Choices / CMP).
- Add original content (guides, FAQs, blog posts). Single-tool sites with little text are often rejected.
- Never place ads on error pages, and never click your own ads.

## Know before launching
- Bandwidth cost: every download passes through YOUR server, so you pay for it. Keep MAX_MB sensible,
  watch usage, and consider Cloudflare in front.
- Legal: don't promote downloading copyrighted material; AdSense bans that and you may be liable. Respond to takedown emails.
- Rate limiting is in-memory per instance. For heavy traffic add Cloudflare or Redis.
- DNS rebinding can still partly evade the private-IP check; run on a host with no access to internal networks.
