#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_domain.py — stamp the domain from .env into every static artifact.

This is the ONE command to run after editing .env. It makes the site ready to go
live on your domain (GitHub Pages custom domain OR cPanel), at the ROOT:

  1. CNAME            <- SITE_DOMAIN            (GitHub Pages custom domain)
  2. robots.txt       <- Sitemap: SITE_URL/sitemap.xml
  3. every *.html     <- canonical / og / twitter / hreflang / footer domain
                         rewritten to SITE_URL (http -> https normalised)
  4. site-config.js   <- CONFIGURED default = SITE_URL (runtime authority)
  5. per-page CGT_CONFIG apiBaseUrl / apiSocketUrl <- API_BASE_URL / API_SOCKET_URL

Safe + idempotent: only URLs on the *known* old host(s) are touched, and re-runs
cleanly replace old->new (the previous domain is read back from CNAME / the
stamped CONFIGURED value). Nothing else is modified. `git checkout .` reverts all.

Usage:
  python build_domain.py            # apply
  python build_domain.py --dry-run  # show what would change, write nothing
"""
import re, os, sys, subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
DRY = '--dry-run' in sys.argv

SC_PATH = os.path.join('assets', 'js', 'site-config.js')


def parse_env(path):
    cfg = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#') or '=' not in s:
                continue
            k, v = s.split('=', 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg


def host_of(url):
    """Bare lowercase host: strip scheme, path/query/fragment, leading www."""
    h = re.sub(r'^https?://', '', (url or '').strip(), flags=re.I)
    h = re.split(r'[/?#]', h, 1)[0]
    h = re.sub(r'^www\.', '', h, flags=re.I)
    return h.lower()


# ---- read .env -------------------------------------------------------------
if not os.path.exists('.env'):
    sys.exit("ERROR: .env not found. Copy .env.example to .env and set your domain.")
cfg = parse_env('.env')

NEW = cfg.get('SITE_URL', '').strip().rstrip('/')
if not NEW:
    sys.exit("ERROR: SITE_URL is empty in .env")
if not re.match(r'^https?://', NEW, re.I):
    NEW = 'https://' + NEW
SITE_DOMAIN = cfg.get('SITE_DOMAIN', '').strip() or host_of(NEW)
API_BASE = cfg.get('API_BASE_URL', '').strip()
API_SOCK = cfg.get('API_SOCKET_URL', '').strip()
REPLACE_COM = cfg.get('REPLACE_LEGACY_DOTCOM', 'true').strip().lower() in ('1', 'true', 'yes', 'on')

# ---- known OLD host(s) to replace -----------------------------------------
known = {'cryptographytube.org'}
if REPLACE_COM:
    known.add('cryptographytube.com')
if os.path.exists('CNAME'):
    known.add(host_of(open('CNAME', encoding='utf-8').read()))
sc_text = None
if os.path.exists(SC_PATH):
    sc_text = open(SC_PATH, encoding='utf-8').read()
    m = re.search(r"var CONFIGURED = '([^']*)';", sc_text)
    if m and m.group(1):
        known.add(host_of(m.group(1)))
known.discard('')

host_alt = '|'.join(re.escape(h) for h in sorted(known, key=len, reverse=True))
# scheme + optional www + known host, bounded so we never eat a longer host.
ORIGIN_RE = re.compile(
    r'https?://(?:www\.)?(?:' + host_alt + r')(?=[/"\'?#:]|\s|$)', re.IGNORECASE)


def sub_field(text, field, value):
    """Set  field: '<value>'  inside an inline CGT_CONFIG (idempotent)."""
    return re.subn(r"(" + field + r":\s*')[^']*(')",
                   lambda m: m.group(1) + value + m.group(2), text)[0]


print("Domain -> %s   (CNAME host: %s)" % (NEW, SITE_DOMAIN))
print("Rewriting URLs on host(s): %s" % ', '.join(sorted(known)))
if API_BASE or API_SOCK:
    print("API: base=%r socket=%r" % (API_BASE, API_SOCK))
if DRY:
    print("--- DRY RUN: no files will be written ---")
print()

# ---- 1) rewrite every HTML page -------------------------------------------
pages = subprocess.check_output(['git', 'ls-files', '*.html'], text=True).splitlines()
pages = [p for p in pages if p != '404.html' and not p.lower().endswith('.dat.html')]

html_changed = seo_hits = 0
for p in pages:
    try:
        t = orig = open(p, encoding='utf-8').read()
    except (UnicodeDecodeError, FileNotFoundError):
        continue
    hits = len(ORIGIN_RE.findall(t))
    t = ORIGIN_RE.sub(lambda m: NEW, t)
    if 'apiBaseUrl:' in t:
        t = sub_field(t, 'apiBaseUrl', API_BASE)
    if 'apiSocketUrl:' in t:
        t = sub_field(t, 'apiSocketUrl', API_SOCK)
    if t != orig:
        html_changed += 1
        seo_hits += hits
        if not DRY:
            open(p, 'w', encoding='utf-8', newline='').write(t)

# ---- 2) CNAME --------------------------------------------------------------
cname_msg = "CNAME -> %s" % SITE_DOMAIN
if not DRY:
    open('CNAME', 'w', encoding='utf-8', newline='').write(SITE_DOMAIN + '\n')

# ---- 3) robots.txt Sitemap line -------------------------------------------
robots_msg = "robots.txt: no change"
if os.path.exists('robots.txt'):
    r = open('robots.txt', encoding='utf-8').read()
    r2 = re.sub(r'(?mi)^Sitemap:.*$', 'Sitemap: %s/sitemap.xml' % NEW, r)
    if r2 != r:
        robots_msg = "robots.txt Sitemap -> %s/sitemap.xml" % NEW
        if not DRY:
            open('robots.txt', 'w', encoding='utf-8', newline='').write(r2)

# ---- 4) stamp site-config.js CONFIGURED default ---------------------------
sc_msg = "site-config.js: not found (run _apply_site_config.py first)"
if sc_text is not None:
    sc2 = re.sub(r"var CONFIGURED = '[^']*';",
                 lambda m: "var CONFIGURED = '%s';" % NEW, sc_text)
    sc_msg = "site-config.js CONFIGURED -> %s" % NEW if sc2 != sc_text else "site-config.js: already current"
    if sc2 != sc_text and not DRY:
        open(SC_PATH, 'w', encoding='utf-8', newline='').write(sc2)

# ---- summary ---------------------------------------------------------------
verb = "would update" if DRY else "updated"
print("%s %d HTML page(s)  (%d domain URL(s) rewritten)" % (verb, html_changed, seo_hits))
print(cname_msg)
print(robots_msg)
print(sc_msg)
if not DRY:
    print("\nDone. Next: commit & push (GitHub Pages) or upload to public_html (cPanel).")
