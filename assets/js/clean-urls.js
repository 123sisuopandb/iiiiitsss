/**
 * Clean URLs for static hosting (GitHub Pages / Netlify / cPanel)
 * ---------------------------------------------------------------
 * The production site serves pretty routes ("/private-keys",
 * "/private-keys/bitcoin"). The static export ships real ".html" files, so the
 * address bar shows "/private-keys.html". GitHub Pages serves the SAME file at
 * the clean path (verified: "/private-keys" === "/private-keys.html"), so this
 * script makes the visible URL match production without breaking any route.
 *
 * Loads in <head>, ABOVE app.obf.js, so the address bar is cleaned as early as
 * possible and any later script that reads location.pathname sees the clean
 * path (the app + every fix script already accept an optional ".html").
 *
 * SAFE because "/foo.html" and "/foo" share the same containing directory
 * ("/"), and "/a/b.html" and "/a/b" share "/a/" — so stripping ".html" (without
 * adding a trailing slash) never changes how relative links resolve.
 */
(function () {
    'use strict';

    // A same-origin path -> its clean form, or null if it should be left as-is.
    function cleanPath(path) {
        if (!path) return null;
        if (path.indexOf('/assets/') !== -1) return null;   // asset files: leave alone
        if (/\.dat\.html$/i.test(path)) return null;        // data dumps: keep extension
        if (/\/index\.html$/i.test(path)) return path.replace(/\/index\.html$/i, '/');
        if (/\.html$/i.test(path)) return path.replace(/\.html$/i, '');
        return null;
    }

    // On the LOCAL dev server a stale cached 301 from an earlier server run can
    // append a trailing slash (e.g. "/private-keys/"), which looks wrong in the
    // address bar. Strip it — address bar only, localhost only — so production
    // (where a trailing slash is the real directory route) is never touched.
    function localTidy(path) {
        var host = location.hostname;
        var isLocal = host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
        if (!isLocal || !path || path === '/') return null;
        if (path.indexOf('/assets/') !== -1) return null;
        if (/\/$/.test(path)) return path.replace(/\/+$/, '');
        return null;
    }

    // ---- (1) Clean the address bar for THIS page (synchronous, no reload) ------
    try {
        var cp = cleanPath(location.pathname) || localTidy(location.pathname);
        if (cp && cp !== location.pathname && window.history && history.replaceState) {
            history.replaceState(history.state, document.title, cp + location.search + location.hash);
        }
    } catch (e) {}

    // ---- (2) Rewrite plain internal ".html" links so clicks stay clean too -----
    // Conservative: only touch anchors WITHOUT a query string and NOT pointing at
    // /key (cgt-static-nav-fix.js owns those, and part 1 cleans the bar on land).
    // This covers the header nav, footer and content cross-links.
    function cleanAnchor(a) {
        var h = a.getAttribute('href');
        if (!h) return;
        if (h.indexOf('?') !== -1 || h.indexOf('#') !== -1) return;   // nav params/anchors: skip
        if (/^[a-z][a-z0-9+.-]*:/i.test(h)) return;                    // has a scheme (http:, mailto:, ...)
        if (h.indexOf('//') === 0) return;                             // protocol-relative
        if (/(^|\/)key\.html$/i.test(h) || h.indexOf('/key/') !== -1) return; // key details: cgt-managed
        if (!/\.html$/i.test(h) || /\.dat\.html$/i.test(h)) return;
        var cleaned;
        if (/(^|\/)index\.html$/i.test(h)) {
            // "./index.html" -> "./", "../index.html" -> "../", "/index.html" -> "/",
            // "foo/index.html" -> "foo/", bare "index.html" -> "./"
            cleaned = h.replace(/index\.html$/i, '') || './';
        } else {
            cleaned = h.replace(/\.html$/i, '');
        }
        if (cleaned && cleaned !== h) a.setAttribute('href', cleaned);
    }

    function cleanAll() {
        try {
            var links = document.getElementsByTagName('a');
            for (var i = 0; i < links.length; i++) cleanAnchor(links[i]);
        } catch (e) {}
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', cleanAll);
    } else {
        cleanAll();
    }
})();
