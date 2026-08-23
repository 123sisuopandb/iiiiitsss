/**
 * CGT Site Config — one-place domain / auto-detect (root deploys)
 * ---------------------------------------------------------------
 * This is the runtime half of the site's single-source-of-truth domain setup.
 * Its companion is the repo-root `.env` + `build_domain.py`, which STAMP the
 * chosen domain into the static files a browser cannot set (CNAME, robots.txt,
 * and the CONFIGURED value just below).
 *
 * Loads in <head> (injected right before </head> by _apply_site_config.py), so
 * every SEO tag above it — canonical, og:*, twitter:*, hreflang — is already in
 * the DOM and can be corrected synchronously, before any crawler-visible paint.
 *
 * Behaviour:
 *   - CONFIGURED set  -> that domain is authoritative (SEO points there even on
 *                        a preview/staging host).
 *   - CONFIGURED empty-> pure AUTO-DETECT: SEO points at the live location.origin,
 *                        so dropping the site on ANY domain "just works" with no
 *                        edits and no build step.
 *
 * It only ever rewrites URLs that still carry the baked-in default host
 * (cryptographytube.org / .com, http or https, optional www). It does NOT touch
 * window.CGT_CONFIG or navigation — at a domain root those already work.
 */
(function () {
    'use strict';

    // <<DOMAIN>> managed by build_domain.py — do not edit by hand.
    var CONFIGURED = '';
    // <</DOMAIN>>

    try {
        var origin = location.origin || (location.protocol + '//' + location.host);
        var target = CONFIGURED || origin;

        // Expose the resolved site info for any later script that wants it.
        window.CGT_SITE = { url: target, origin: origin, configured: CONFIGURED };

        // Match the baked default host only (scheme + optional www + .org/.com),
        // so user content and third-party URLs are never rewritten.
        var LEGACY = /^https?:\/\/(www\.)?cryptographytube\.(org|com)/i;

        function fix(selector, attr) {
            var els = document.querySelectorAll(selector);
            for (var i = 0; i < els.length; i++) {
                var v = els[i].getAttribute(attr);
                if (v && LEGACY.test(v)) {
                    els[i].setAttribute(attr, v.replace(LEGACY, target));
                }
            }
        }

        fix('link[rel="canonical"]', 'href');
        fix('link[rel="alternate"][hreflang]', 'href');
        fix('meta[property="og:url"]', 'content');
        fix('meta[property="og:image"]', 'content');
        fix('meta[name="twitter:image"]', 'content');
    } catch (e) { /* never block page load */ }
})();
