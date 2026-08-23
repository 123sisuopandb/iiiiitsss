/**
 * CGT rsz-vulnerable-addresses  (assets/js/rsz-vulnerable-addresses.js)
 * ------------------------------------------------------------------
 * Client-side engine for the "RSZ Vulnerable Addresses" tracker — the list of
 * ECDSA nonce-reuse (RSZ) Bitcoin addresses shipped in /rszvul.txt. Nothing is
 * pre-rendered: both the list and every detail sub-page are produced at runtime
 * from the txt, so adding/removing addresses is a one-file edit.
 *
 *  1. LIST PAGE  (/rsz-vulnerable-addresses)
 *     Loads /rszvul.txt, renders it into #rsz-table 50 rows at a time with
 *     IN-PAGE pagination (#rszPagination) and a client-side filter (#rsz-search).
 *     Live balances reuse the site's shared BalanceChecker batch call
 *     (assets/js/balance-checker.obf.js) with the same .balance-cell markup the
 *     bitcoin-dormant tracker uses.
 *
 *  2. DETAIL SUB-PAGE  (/rszvuln/address.html?a=<ADDR>)
 *     One template renders ANY address: this script reads ?a= from the query
 *     string, validates it, fills the header / info table / explorer + analysis
 *     links, and fetches the live balance itself via BalanceChecker.
 *
 * Robust by design: a missing/empty txt shows "No addresses" (no hard failure);
 * balances degrade to "-" if BalanceChecker is unavailable; the copy buttons use
 * the site-wide CryptographyTube.copy (with a tiny clipboard fallback).
 */
(function () {
  'use strict';

  var PER_PAGE = 50;
  var VER      = 'cgtrsz1';
  var DATA_URL = '/rszvul.txt';
  var DETAIL   = '/rszvuln/address.html';   // detail template (query-param routed)

  // ---- tiny helpers ---------------------------------------------------------
  function $(sel, root)    { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function setText(id, v)  { var el = document.getElementById(id); if (el && v != null) el.textContent = v; }

  // Loose BTC address check (P2PKH / P2SH base58 + bech32). Good enough to reject
  // junk lines in the txt without pulling in a full validator.
  function isBtcAddress(a) {
    return typeof a === 'string' &&
      /^(bc1[ac-hj-np-z02-9]{6,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$/.test(a);
  }

  // Detail-page URL for an address (kept with .html + query so it resolves on any
  // static host; clean-urls.js leaves ?-bearing links alone and prettifies the bar
  // to /rszvuln/address on landing).
  function detailHref(addr) { return DETAIL + '?a=' + encodeURIComponent(addr); }

  // ---- rszvul.txt -----------------------------------------------------------
  // One address per line. Blank lines and lines starting with '#' are ignored.
  // Duplicate addresses are dropped, original order preserved.
  function parseTxt(text) {
    var out = [], seen = {};
    var lines = String(text || '').split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var addr = lines[i].trim();
      if (!addr || addr.charAt(0) === '#') continue;
      if (!isBtcAddress(addr) || seen[addr]) continue;
      seen[addr] = 1;
      out.push({ address: addr });
    }
    return out;
  }

  var _txt = null;
  function loadTxt() {
    if (_txt) return _txt;
    _txt = fetch(DATA_URL + '?v=' + VER, { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.text() : ''; })
      .then(parseTxt)
      .catch(function () { return []; });
    return _txt;
  }

  // ---- clipboard: prefer the site-wide helper, fall back to the Clipboard API --
  function ensureCopy() {
    if (window.CryptographyTube && typeof window.CryptographyTube.copy === 'function') return;
    window.CryptographyTube = window.CryptographyTube || {};
    window.CryptographyTube.copy = function (text) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text); return; }
      } catch (e) {}
      try {
        var ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy');
        document.body.removeChild(ta);
      } catch (e) {}
    };
  }

  // ---- balances (reuse the engine's exact batch call + cell markup) ---------
  function balanceCellHtml(entry) {
    if (entry && parseFloat(entry.balanceStr) > 0) {
      return '<span class="text-success fw-bold">' + entry.balanceStr +
             '</span> <small class="fw-normal">BTC</small>';
    }
    if (entry) {
      return '<span class="text-muted">0</span> <small class="text-muted">BTC</small>';
    }
    return '<span class="text-muted">-</span>';
  }

  function hasBalanceChecker() {
    return typeof window.BalanceChecker !== 'undefined' &&
           typeof window.BalanceChecker.fetchBitcoinBalancesBatch === 'function';
  }

  function fillBalances(addrs) {
    if (!addrs.length) return;
    function paint(map) {
      $all('#rsz-table .key-row').forEach(function (row) {
        var addr = row.getAttribute('data-address');
        if (addrs.indexOf(addr) === -1) return;
        var cell = $('.balance-cell', row);
        if (!cell) return;
        cell.innerHTML = balanceCellHtml(map && map.has(addr) ? map.get(addr) : null);
      });
    }
    if (!hasBalanceChecker()) { paint(null); return; }
    window.BalanceChecker.fetchBitcoinBalancesBatch(addrs)
      .then(paint)
      .catch(function () { paint(null); });
  }

  // ---- row rendering --------------------------------------------------------
  function rowHtml(e) {
    var a = e.address;
    return '' +
      '<div class="key-row" data-address="' + a + '">' +
        '<div class="col-address">' +
          '<a href="' + detailHref(a) + '" class="address-link font-monospace">' + a + '</a>' +
          '<button class="copy-btn" onclick="CryptographyTube.copy(\'' + a + '\')" title="Copy">' +
            '<img src="/assets/svgs/regular/copy.svg" class="fa-icon " width="12" height="12" alt="">' +
          '</button>' +
        '</div>' +
        '<div class="col-balance balance-cell">' +
          '<span class="balance-loading"><img src="/assets/svgs/solid/spinner.svg" class="fa-icon fa-spin" width="14" height="14" alt=""></span>' +
        '</div>' +
        '<div class="col-vuln"><span class="badge bg-danger">Nonce Reuse</span></div>' +
        '<div class="col-action">' +
          '<a href="' + detailHref(a) + '" class="detail-link" title="View Details">' +
            '<img src="/assets/svgs/solid/circle-info.svg" class="fa-icon " width="12" height="12" alt=""> <span class="detail-text">Details</span>' +
          '</a>' +
        '</div>' +
      '</div>';
  }

  // ---- pagination -----------------------------------------------------------
  function pageWindow(current, total) {
    // 1 … (c-1) c (c+1) … total — de-duplicated, ordered, 0 = ellipsis marker
    var s = {};
    s[1] = 1; s[total] = total;
    for (var d = -1; d <= 1; d++) { var n = current + d; if (n >= 1 && n <= total) s[n] = n; }
    var nums = Object.keys(s).map(Number).sort(function (a, b) { return a - b; });
    var out = [];
    for (var i = 0; i < nums.length; i++) {
      if (i && nums[i] - nums[i - 1] > 1) out.push(0);
      out.push(nums[i]);
    }
    return out;
  }

  var IC = {
    first: '/assets/svgs/solid/angles-left.svg',
    prev:  '/assets/svgs/solid/angle-left.svg',
    next:  '/assets/svgs/solid/angle-right.svg',
    last:  '/assets/svgs/solid/angles-right.svg',
    go:    '/assets/svgs/solid/arrow-right.svg'
  };
  function icon(src) { return '<img src="' + src + '" class="fa-icon " width="12" height="12" alt="">'; }

  // ---- LIST page controller -------------------------------------------------
  var list = { all: [], filtered: [], page: 1 };

  function totalPages() { return Math.max(1, Math.ceil(list.filtered.length / PER_PAGE)); }

  function buildPagination() {
    var nav = document.getElementById('rszPagination');
    if (!nav) return;
    var current = list.page, total = totalPages();

    function navBtn(target, ic, title, enabled) {
      return enabled
        ? '<button type="button" class="btn btn-sm btn-outline-secondary" data-rsz-page="' + target + '" title="' + title + '">' + icon(ic) + '</button>'
        : '<button type="button" class="btn btn-sm btn-outline-secondary" disabled>' + icon(ic) + '</button>';
    }

    var pages = pageWindow(current, total).map(function (n) {
      if (n === 0) return '<span class="btn btn-sm btn-outline-secondary disabled">...</span>';
      if (n === current) return '<span class="btn btn-sm btn-primary">' + n + '</span>';
      return '<button type="button" class="btn btn-sm btn-outline-secondary" data-rsz-page="' + n + '">' + n + '</button>';
    }).join('');

    nav.innerHTML = '' +
      '<div class="d-flex flex-wrap align-items-center justify-content-center gap-2">' +
        '<div class="pagination-nav">' +
          navBtn(1, IC.first, 'First', current > 1) +
          navBtn(current - 1, IC.prev, 'Previous', current > 1) +
        '</div>' +
        '<div class="pagination-pages d-none d-sm-flex gap-1">' + pages + '</div>' +
        '<div class="pagination-info d-sm-none">' +
          '<span class="btn btn-sm btn-outline-secondary disabled">' + current + ' / ' + total + '</span>' +
        '</div>' +
        '<div class="pagination-nav">' +
          navBtn(current + 1, IC.next, 'Next', current < total) +
          navBtn(total, IC.last, 'Last', current < total) +
        '</div>' +
      '</div>' +
      '<div class="d-flex align-items-center justify-content-center gap-2 mt-2">' +
        '<span class="text-muted small">Go to page:</span>' +
        '<input type="number" class="form-control form-control-sm" id="rszPaginationInput" ' +
               'min="1" max="' + total + '" style="width: 80px;" value="' + current + '">' +
        '<button type="button" class="btn btn-sm btn-primary" id="rszPaginationGo">' + icon(IC.go) + ' Go</button>' +
        '<span class="text-muted small ms-2">of ' + total + ' pages</span>' +
      '</div>';

    // in-page navigation (no reload): numbered + first/prev/next/last buttons
    $all('[data-rsz-page]', nav).forEach(function (btn) {
      btn.addEventListener('click', function () {
        goToPage(parseInt(btn.getAttribute('data-rsz-page'), 10));
      });
    });
    var input = document.getElementById('rszPaginationInput');
    var go = document.getElementById('rszPaginationGo');
    function jump() { goToPage(parseInt(input.value, 10) || 1); }
    if (go) go.addEventListener('click', jump);
    if (input) input.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') jump(); });
  }

  function goToPage(n) {
    var total = totalPages();
    n = Math.max(1, Math.min(total, isNaN(n) ? 1 : n));
    if (n === list.page) return;
    list.page = n;
    renderPage();
    var table = document.getElementById('rsz-table');
    if (table && table.scrollIntoView) table.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderPage() {
    var table = document.getElementById('rsz-table');
    if (!table) return;
    $all('.key-row', table).forEach(function (r) { r.parentNode.removeChild(r); });
    var empty = $('#rsz-empty', table);
    if (empty) empty.parentNode.removeChild(empty);

    var start = (list.page - 1) * PER_PAGE;
    var slice = list.filtered.slice(start, start + PER_PAGE);

    if (!slice.length) {
      table.insertAdjacentHTML('beforeend',
        '<div id="rsz-empty" class="p-4 text-center text-muted">No matching addresses.</div>');
    } else {
      table.insertAdjacentHTML('beforeend', slice.map(rowHtml).join(''));
      fillBalances(slice.map(function (e) { return e.address; }));
    }

    buildPagination();

    // "Showing 1–50 of N" indicator
    var info = document.getElementById('rsz-showing');
    if (info) {
      info.textContent = slice.length
        ? 'Showing ' + (start + 1) + '–' + (start + slice.length) + ' of ' + list.filtered.length +
          (list.filtered.length !== list.all.length ? ' (filtered from ' + list.all.length + ')' : '')
        : 'No matching addresses';
    }
  }

  function wireSearch() {
    var box = document.getElementById('rsz-search');
    if (!box) return;
    var t = null;
    box.addEventListener('input', function () {
      clearTimeout(t);
      t = setTimeout(function () {
        var q = box.value.trim().toLowerCase();
        list.filtered = q
          ? list.all.filter(function (e) { return e.address.toLowerCase().indexOf(q) !== -1; })
          : list.all;
        list.page = 1;
        renderPage();
      }, 120);
    });
  }

  function updateCounts() {
    var n = list.all.length;
    setText('rsz-stat-total', n.toLocaleString('en-US'));
    var badge = document.getElementById('rsz-count-badge');
    if (badge) badge.textContent = n.toLocaleString('en-US') + ' addresses';
  }

  function initList() {
    ensureCopy();
    wireSearch();
    loadTxt().then(function (txt) {
      list.all = txt;
      list.filtered = txt;
      list.page = 1;
      updateCounts();
      renderPage();
    });
  }

  // ---- DETAIL sub-page ------------------------------------------------------
  function queryAddr() {
    var m = /[?&]a=([^&]+)/.exec(location.search);
    if (!m) return '';
    try { return decodeURIComponent(m[1]).trim(); } catch (e) { return m[1].trim(); }
  }

  function fillDetailBalance(addr) {
    var el = document.getElementById('current-balance');
    if (!el) return;
    if (!hasBalanceChecker()) { el.innerHTML = '<span class="text-muted">-</span>'; return; }
    window.BalanceChecker.fetchBitcoinBalancesBatch([addr]).then(function (map) {
      el.innerHTML = balanceCellHtml(map && map.has(addr) ? map.get(addr) : null);
    }).catch(function () {
      el.innerHTML = '<span class="text-muted">-</span>';
    });
  }

  function initDetail() {
    ensureCopy();
    var addr = queryAddr();
    var valid = isBtcAddress(addr);

    if (valid) {
      document.title = 'RSZ Vulnerable Address ' + addr + ' - CryptographyTube';
      var can = document.querySelector('link[rel="canonical"]');
      if (can) can.setAttribute('href', location.origin + detailHref(addr));
    }

    // address-bearing spots
    $all('.detail-address').forEach(function (el) {
      el.textContent = valid ? addr : (addr ? addr + ' (invalid)' : 'No address supplied');
    });
    setText('d-address-full', valid ? addr : (addr || '(none)'));
    setText('d-crumb', valid ? (addr.length > 14 ? addr.slice(0, 10) + '…' : addr) : 'Address');

    // header actions: copy + explorer
    var copyBtn = document.querySelector('.detail-header-actions .btn-outline-primary');
    if (copyBtn && valid) copyBtn.setAttribute('onclick', "CryptographyTube.copy('" + addr + "')");
    var expl = document.querySelector('.detail-header-actions a.btn-primary');
    if (expl && valid) expl.href = 'https://www.blockchain.com/explorer/addresses/btc/' + addr;

    // secondary explorer + analysis deep-links
    var mempool = document.getElementById('rsz-explorer-mempool');
    if (mempool && valid) mempool.href = 'https://mempool.space/address/' + addr;
    var analyze = document.getElementById('rsz-analyze-link');
    if (analyze && valid) analyze.href = '/txid-rsz-recovery/?address=' + encodeURIComponent(addr);

    if (!valid) {
      var b = document.getElementById('current-balance');
      if (b) b.innerHTML = '<span class="text-muted">-</span>';
      // hide action buttons that need a valid address
      $all('.detail-header-actions a, .detail-header-actions button').forEach(function (el) {
        el.classList.add('disabled');
        if (el.tagName === 'A') el.removeAttribute('href');
      });
      return;
    }
    fillDetailBalance(addr);
  }

  // ---- dispatch -------------------------------------------------------------
  function boot() {
    if (document.querySelector('.rsz-detail') && document.getElementById('current-balance')) {
      initDetail();
    } else if (document.getElementById('rsz-table')) {
      initList();
    }
  }

  // `defer` scripts run after the DOM is parsed, so the DOM is ready here; guard
  // anyway in case this is ever loaded without defer.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
