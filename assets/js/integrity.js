/**
 * Page integrity fingerprint  (bitaddress.org-style, adapted for a live multi-page site)
 * -------------------------------------------------------------------------------------
 * bitaddress.org ships ONE self-contained file whose SHA-256 is baked into the filename,
 * so anyone can verify it offline. We can't put the hash in 1,533 filenames (it would
 * break clean URLs + internal links + SEO), so instead every page fingerprints ITSELF at
 * load: it fetches its own served HTML, computes the SHA-256, and shows it in the address
 * bar as "#SHA256-<64hex>". Anyone can confirm it independently:
 *
 *     sha256sum thepage.html                  ==  the value shown here
 *     curl --compressed -s <url> | sha256sum  ==  the value shown here
 *
 * HONEST SCOPE — this is a *fingerprint*, not an authenticity guarantee. It catches
 * accidental corruption and in-transit HTML rewriting, and lets anyone who already holds
 * an out-of-band expected hash compare at a glance. It does NOT prove the server wasn't
 * compromised: the page hashes itself with a script from the same origin, and the external
 * /assets/js/*.js it loads are not covered. So the fragment is labeled "#SHA256-", never
 * "verified/secure".
 *
 * DISPLAY IS ADDRESS-BAR ONLY — no on-page badge (removed by request, to keep the UI
 * clean). The hex is also exposed as window.CGT_PAGE_SHA256 for the console / other scripts.
 *
 * Design (mirrors clean-urls.js): IIFE, 'use strict', every step wrapped so a failure can
 * never block the page. Uses history.replaceState (never assigns location.hash) so it fires
 * no hashchange and causes no scroll, and only writes the fragment when none — or a prior
 * #SHA256- of ours — is present, so a real anchor is never clobbered. Hashes
 * location.pathname WITHOUT the query (the static host returns the same bytes for any
 * ?query, and offline verification targets the .html file), which also lets force-cache
 * reuse the navigation response.
 */
(function () {
    'use strict';

    // Secure-context + API guard. On plain HTTP (crypto.subtle absent) or an ancient
    // browser this simply does nothing — the page is unaffected.
    if (!(window.crypto && window.crypto.subtle && window.TextEncoder &&
          window.fetch && window.history && history.replaceState)) return;

    function toHex(buf) {
        var b = new Uint8Array(buf), s = '', i;
        for (i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
        return s;
    }

    // Reflect the hash in the address bar, bitaddress-style, without breaking anything.
    function showFragment(hex) {
        try {
            // Never clobber a foreign fragment (e.g. a shared "#section" deep link);
            // only write when the bar is bare or already carries an earlier #SHA256- of ours.
            if (!location.hash || /^#SHA256-/i.test(location.hash)) {
                history.replaceState(history.state, document.title,
                    location.pathname + location.search + '#SHA256-' + hex);
            }
        } catch (e) {}
    }

    function go() {
        try {
            // Fetch the served file for THIS path (no query). A non-2xx (e.g. a GitHub
            // Pages 404-SPA route that is assembled client-side) yields no fingerprint —
            // there is no single canonical file to hash there, so we correctly show nothing.
            fetch(location.pathname, { cache: 'force-cache', credentials: 'same-origin' })
                .then(function (res) { return (res && res.ok) ? res.text() : null; })
                .then(function (text) {
                    if (text == null) return null;
                    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
                })
                .then(function (buf) {
                    if (!buf) return;
                    var hex = toHex(buf);
                    window.CGT_PAGE_SHA256 = hex;           // exposed for console / other scripts
                    showFragment(hex);
                })
                .catch(function () {});                     // never block the page
        } catch (e) {}
    }

    // This script is injected `defer`, so the DOM is fully parsed when it runs. Run as soon
    // as the DOM is ready; the fetch + digest are async and off the main thread either way.
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go);
    else go();
})();
