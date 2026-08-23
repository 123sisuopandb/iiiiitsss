/*
 * Bitcoin Address Analysis — data controller.
 *
 * Loads AFTER arf.js (the vendored OSINT-Framework d3 tree engine) and shares
 * its global scope. It never touches the tree/zoom/search mechanics — it only:
 *   1. fetches a Bitcoin address's transactions from the blockchain.info API,
 *   2. turns them into a {name, children[]} hierarchy the engine can render,
 *   3. drives clicks (open detail box + lazy-expand a node's own txs),
 *   4. populates the detail box with blockchain fields.
 *
 * DATA SOURCE: blockchain.info PRIMARY, blockstream.info (Esplora) FALLBACK.
 * No mempool.space, no blockchair. blockchain.info's `/address/{addr}?format=json`
 * endpoint (the caller's proven approach) returns address stats AND transactions
 * in one CORS-enabled call (`&cors=true`, 100 txs/page via `&offset=`). If it is
 * unreachable or rate-limiting, we transparently fall back to blockstream.info's
 * Esplora API and normalise its response into the same tx shape, so the tree
 * builder never has to know which explorer served the data.
 *
 * Public keys are shown only when revealed on-chain (an address reveals its
 * pubkey the first time it *spends*); otherwise we say "not revealed yet".
 */
(function () {
  "use strict";

  // PRIMARY: blockchain.info. `&cors=true` makes it send
  // `Access-Control-Allow-Origin: *`, so it is callable straight from the
  // browser. FALLBACK: blockstream.info Esplora (also CORS `*`).
  var API_BCI = "https://blockchain.info";
  var API_ESPLORA = "https://blockstream.info/api";
  var TX_LIMIT = 100;            // newest txs fetched per address for the tree;
                                 // user-adjustable via the #aa-tx-limit selector
                                 // (100/200/300/500) — see wireTxLimit().
  var MAX_COUNTERPARTIES = 40;   // cap counterparty children per transaction
  var txCache = {};              // address -> normalised txs array (avoid refetch)
  var lastSource = "";           // which explorer served the most recent fetch
  var activeChain = null;        // the CHAINS entry currently selected (set in init)

  function $(id) { return document.getElementById(id); }

  function esc(str) {
    return (str == null ? "" : String(str))
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function setStatus(msg, kind) {
    var el = $("aa-status");
    if (!el) return;
    el.textContent = msg || "";
    el.className = kind || "";
  }

  function shorten(str, head, tail) {
    head = head || 10; tail = tail || 8;
    if (!str) return "";
    if (str.length <= head + tail + 1) return str;
    return str.slice(0, head) + "…" + str.slice(-tail);
  }

  // Format a smallest-unit integer amount (satoshi / wei / drops / sun / nanoton…)
  // as a human string for the given chain. Each chain declares its `decimals`
  // (8 for bitcoin-family, 18 for EVM, 6 for tron/xrp, 9 for ton/sui/solana) and
  // `symbol`. Display is capped at 8 fractional digits so 18-decimal chains stay
  // readable. Falls back to the active chain, then Bitcoin, when none is passed.
  function formatValue(amount, chain) {
    chain = chain || activeChain || CHAINS.bitcoin;
    var dec = (chain && chain.decimals != null) ? chain.decimals : 8;
    var sym = (chain && chain.symbol) || "BTC";
    if (amount == null) return "0 " + sym;
    var num = Number(amount);          // tolerate BigInt / numeric-string / number
    if (isNaN(num)) return "0 " + sym;
    var human = num / Math.pow(10, dec);
    var s = human.toFixed(Math.min(dec, 8)).replace(/0+$/, "").replace(/\.$/, "");
    return (s === "" ? "0" : s) + " " + sym;
  }

  // Shorthand used by every shared builder/renderer. It formats amounts for the
  // CURRENTLY-ANALYSED chain (never cross-chain), so delegating to `activeChain`
  // makes all the existing Bitcoin call sites chain-correct with zero churn.
  // (Before init, activeChain is null → formatValue falls back to Bitcoin.)
  function formatBTC(sat) { return formatValue(sat, activeChain); }

  // Accept mainnet legacy (1.. / 3..) and bech32 / bech32m (bc1..) addresses.
  function isProbablyBtcAddress(a) {
    a = (a || "").trim();
    return /^(bc1[ac-hj-np-z02-9]{6,90})$/i.test(a) ||
           /^[13][a-km-zA-HJ-NP-Z1-9]{25,39}$/.test(a);
  }

  // A transaction ID is exactly 64 hex characters. No Bitcoin address is 64 hex,
  // so this is unambiguous and lets the single input box accept an address OR a TXID.
  function isProbablyTxid(s) {
    return /^[0-9a-fA-F]{64}$/.test((s || "").trim());
  }

  // ---------- data fetch: blockchain.info primary, blockstream fallback ----------
  // Both paths resolve to ONE normalised shape (blockchain.info's native shape):
  //   { address, n_tx, total_received, total_sent, final_balance,
  //     txs:[ { hash, result?, fee, time, block_height,
  //             inputs:[{prev_out:{addr,value,script}, script, witnessItems?}],
  //             out:[{addr,value}] } ], source }
  // `result` (net sats for the queried address) is provided by blockchain.info;
  // for Esplora we omit it and buildTxChildren computes net = sumOut - sumIn.
  function okJson(r) {
    if (r.status === 429) throw new Error("rate-limited");
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }

  // PRIMARY — the caller's proven approach: /address/{addr}?format=json&offset=N
  // (100 txs/page, same tx shape as /rawaddr). We take the newest page and keep
  // the freshest `limit` txs for the tree.
  function fetchBci(addr, limit) {
    var want = limit || TX_LIMIT;
    var all = [], meta = null;
    // blockchain.info returns a page of txs per call (≤50); page through offsets
    // until we have `want` newest txs, hit the end, or a page comes back empty.
    function page(offset) {
      var url = API_BCI + "/address/" + encodeURIComponent(addr) +
                "?format=json&limit=50&offset=" + offset + "&cors=true";
      return fetch(url, { headers: { "Accept": "application/json" } })
        .then(okJson)
        .then(function (d) {
          if (!meta) meta = d;
          var txs = (d && d.txs) || [];
          all = all.concat(txs);
          var total = (meta && meta.n_tx) || all.length;
          if (all.length >= want || txs.length === 0 || all.length >= total) return;
          return page(offset + txs.length);
        })
        .catch(function (e) {
          // Partial success: keep what we already fetched. Total failure (nothing
          // yet) propagates so fetchAddr can fall back to Esplora / surface a hint.
          if (all.length) return;
          throw e;
        });
    }
    return page(0).then(function () {
      return {
        address: (meta && meta.address) || addr,
        n_tx: (meta && meta.n_tx) || all.length,
        total_received: (meta && meta.total_received) || 0,
        total_sent: (meta && meta.total_sent) || 0,
        final_balance: (meta && meta.final_balance) || 0,
        txs: all.slice(0, want),
        source: "blockchain.info"
      };
    });
  }

  // Normalise one Esplora tx into the blockchain.info tx shape.
  function esploraTxToBci(t) {
    var st = t.status || {};
    return {
      hash: t.txid,
      // result omitted on purpose -> buildTxChildren computes the net effect.
      fee: t.fee,
      size: t.size,
      time: st.block_time || null,
      block_height: st.confirmed ? st.block_height : null,
      inputs: (t.vin || []).map(function (v) {
        var po = v.prevout || {};
        return {
          prev_out: {
            addr: po.scriptpubkey_address || null,
            value: po.value || 0,
            script: po.scriptpubkey || null
          },
          script: v.scriptsig || "",
          // Esplora already delivers the witness as an array of hex items.
          witnessItems: Array.isArray(v.witness) ? v.witness : null
        };
      }),
      out: (t.vout || []).map(function (o) {
        return { addr: o.scriptpubkey_address || null, value: o.value || 0 };
      })
    };
  }

  // FALLBACK — blockstream.info Esplora: /address/{addr} for stats +
  // /address/{addr}/txs for the newest txs, normalised to the shape above.
  function fetchEsplora(addr, limit) {
    var base = API_ESPLORA + "/address/" + encodeURIComponent(addr);
    return Promise.all([
      fetch(base).then(okJson),
      fetch(base + "/txs").then(okJson)
    ]).then(function (res) {
      var stats = res[0] || {}, rawTxs = res[1] || [];
      var cs = stats.chain_stats || {}, ms = stats.mempool_stats || {};
      var funded = (cs.funded_txo_sum || 0) + (ms.funded_txo_sum || 0);
      var spent = (cs.spent_txo_sum || 0) + (ms.spent_txo_sum || 0);
      return {
        address: addr,
        n_tx: ((cs.tx_count || 0) + (ms.tx_count || 0)) || rawTxs.length,
        total_received: funded,
        total_sent: spent,
        final_balance: funded - spent,
        txs: rawTxs.slice(0, limit || TX_LIMIT).map(esploraTxToBci),
        source: "blockstream.info"
      };
    });
  }

  // Try blockchain.info first; on ANY problem fall back to blockstream.info.
  function fetchAddr(addr, limit) {
    return fetchBci(addr, limit)
      .then(function (d) { lastSource = d.source; return d; })
      .catch(function (e1) {
        return fetchEsplora(addr, limit)
          .then(function (d) { lastSource = d.source; return d; })
          .catch(function (e2) {
            // Both explorers failed — surface a rate-limit hint if either threw one.
            if (/rate/.test((e1 && e1.message) || "") ||
                /rate/.test((e2 && e2.message) || "")) throw new Error("rate-limited");
            throw e1;
          });
      });
  }

  // ---------- single-transaction fetch (for TXID input) ----------
  // Both explorers resolve to the SAME normalised tx shape buildTxChildren /
  // buildTxRoot already understand (blockchain.info's native /rawtx shape).
  function fetchTxBci(txid) {
    var url = API_BCI + "/rawtx/" + encodeURIComponent(txid) + "?cors=true";
    return fetch(url, { headers: { "Accept": "application/json" } })
      .then(okJson)
      .then(function (t) { t.source = "blockchain.info"; return t; });
  }
  function fetchTxEsplora(txid) {
    return fetch(API_ESPLORA + "/tx/" + encodeURIComponent(txid))
      .then(okJson)
      .then(function (t) { var n = esploraTxToBci(t); n.source = "blockstream.info"; return n; });
  }
  // Try blockchain.info first; on ANY problem fall back to blockstream.info.
  function fetchTx(txid) {
    return fetchTxBci(txid)
      .then(function (t) { lastSource = "blockchain.info"; return t; })
      .catch(function (e1) {
        return fetchTxEsplora(txid)
          .then(function (t) { lastSource = "blockstream.info"; return t; })
          .catch(function (e2) {
            if (/rate/.test((e1 && e1.message) || "") ||
                /rate/.test((e2 && e2.message) || "")) throw new Error("rate-limited");
            throw e1;
          });
      });
  }

  // ---------- public-key extraction (blockchain.info formats) ----------
  function looksLikePubkey(hex) {
    return /^(02|03)[0-9a-fA-F]{64}$/.test(hex) || /^04[0-9a-fA-F]{128}$/.test(hex);
  }
  function pubkeyKind(hex) { return /^04/i.test(hex) ? "uncompressed" : "compressed"; }

  // Legacy P2PKH: scriptsig hex ends with a push of the pubkey (0x21<33B> or 0x41<65B>).
  function pubkeyFromScriptHex(scriptHex) {
    if (!scriptHex) return null;
    var m = /21((?:02|03)[0-9a-fA-F]{64})$/.exec(scriptHex) ||
            /41(04[0-9a-fA-F]{128})$/.exec(scriptHex);
    return m ? { key: m[1], kind: pubkeyKind(m[1]) } : null;
  }

  // blockchain.info serialises a segwit witness as one hex string:
  //   [compactsize item-count][ (compactsize len)(data) ]...
  function parseWitnessItems(witnessHex) {
    if (!witnessHex || typeof witnessHex !== "string") return [];
    var buf = witnessHex.toLowerCase(), pos = 0;
    function byte() { var b = parseInt(buf.substr(pos, 2), 16); pos += 2; return b; }
    function varint() {
      var f = byte();
      if (isNaN(f)) return -1;
      if (f < 0xfd) return f;
      if (f === 0xfd) { var a = byte(), b = byte(); return a + b * 256; }
      return -1; // 0xfe/0xff — unreasonably large, bail
    }
    var count = varint();
    if (count < 0 || count > 100) return [];
    var items = [];
    for (var i = 0; i < count; i++) {
      var len = varint();
      if (len < 0 || pos + len * 2 > buf.length) return items;
      items.push(buf.substr(pos, len * 2));
      pos += len * 2;
    }
    return items;
  }

  // Return { key, kind } if this input reveals a public key, else null.
  function extractPubkey(input) {
    if (!input) return null;
    // P2PKH: pubkey pushed at the tail of the scriptsig.
    var fromScript = pubkeyFromScriptHex(input.script);
    if (fromScript) return fromScript;
    // P2WPKH / nested: witness stack's last item is the compressed pubkey.
    // Esplora gives the witness as an array (witnessItems); blockchain.info gives
    // it as one serialised hex string that we parse into items.
    var items = input.witnessItems || parseWitnessItems(input.witness);
    for (var i = items.length - 1; i >= 0; i--) {
      if (looksLikePubkey(items[i])) return { key: items[i], kind: pubkeyKind(items[i]) };
    }
    // Taproot key-path: x-only key lives in the prevout script (5120<32B>).
    var po = input.prev_out;
    if (po && po.script && /^5120[0-9a-fA-F]{64}$/.test(po.script)) {
      return { key: po.script.slice(4), kind: "x-only (taproot)" };
    }
    return null;
  }

  // ---------- hierarchy building ----------
  // Build the transaction child-nodes for a given "context" address.
  function buildTxChildren(addr, txs) {
    return txs.map(function (tx) {
      var inputs = tx.inputs || [], outs = tx.out || [];
      var sumIn = 0, sumOut = 0;
      inputs.forEach(function (v) {
        if (v.prev_out && v.prev_out.addr === addr) sumIn += v.prev_out.value || 0;
      });
      outs.forEach(function (o) {
        if (o.addr === addr) sumOut += o.value || 0;
      });
      // blockchain.info gives the net effect on the queried address directly.
      var net = (typeof tx.result === "number") ? tx.result : (sumOut - sumIn);
      var direction = net > 0 ? "received" : (net < 0 ? "sent" : "self");

      // The context address's own pubkey is revealed here iff it is a spender.
      var ownPubkey = null;
      if (sumIn > 0) {
        inputs.some(function (v) {
          if (v.prev_out && v.prev_out.addr === addr) {
            var pk = extractPubkey(v);
            if (pk) { ownPubkey = pk; return true; }
          }
          return false;
        });
      }

      // Counterparties: recipients (if we sent) or senders (if we received).
      var cps = [], seen = {}, hidden = 0;
      if (direction === "sent") {
        outs.forEach(function (o) {
          var a = o.addr;
          if (!a || a === addr) return;               // skip self / change / unparsable
          if (seen[a]) { seen[a].value += o.value || 0; return; }
          var n = makeAddressNode(a, o.value || 0, "recipient", null);
          seen[a] = n; cps.push(n);
        });
      } else {
        inputs.forEach(function (v) {
          if (!v.prev_out) return;
          var a = v.prev_out.addr;
          if (!a || a === addr) return;
          var pk = extractPubkey(v);
          if (seen[a]) {
            seen[a].value += v.prev_out.value || 0;
            if (pk && !seen[a].pubkey) seen[a].pubkey = pk;
            return;
          }
          var n = makeAddressNode(a, v.prev_out.value || 0, "sender", pk);
          seen[a] = n; cps.push(n);
        });
      }
      if (cps.length > MAX_COUNTERPARTIES) { hidden = cps.length - MAX_COUNTERPARTIES; cps = cps.slice(0, MAX_COUNTERPARTIES); }

      var confirmed = (tx.block_height != null && tx.block_height > 0);
      var sign = direction === "received" ? "+" : direction === "sent" ? "−" : "±";
      var amt = formatBTC(Math.abs(net) || sumIn || sumOut);
      return {
        name: tx.hash + "   " + sign + amt,
        description: "Transaction " + tx.hash + " — " + direction + " " + sign + amt,
        free: true,
        kind: "tx",
        txid: tx.hash,
        direction: direction,
        dir: direction === "received" ? "in" : direction === "sent" ? "out" : "self",
        net: net, sumIn: sumIn, sumOut: sumOut,
        fee: tx.fee,
        size: tx.size,
        confirmed: confirmed,
        blockHeight: confirmed ? tx.block_height : null,
        blockTime: tx.time,
        ownPubkey: ownPubkey,
        contextAddress: addr,
        hiddenCount: hidden,
        children: cps
      };
    });
  }

  function makeAddressNode(addr, value, role, pubkey) {
    var sign = role === "recipient" ? "−" : "+";
    return {
      name: addr + "   " + sign + formatBTC(value),
      description: addr + " — click to trace its transactions",
      free: true,
      kind: "address",
      address: addr,
      value: value,
      role: role,
      dir: role === "recipient" ? "out" : "in",   // out = money left root, in = money came in
      pubkey: pubkey || null,
      children: null              // lazily loaded on click
    };
  }

  function buildRoot(addr, data) {
    var txs = data.txs || [];
    // Own pubkey across the loaded txs (revealed when this address is a spender).
    var ownPubkey = null;
    txs.some(function (tx) {
      return (tx.inputs || []).some(function (v) {
        if (v.prev_out && v.prev_out.addr === addr) {
          var pk = extractPubkey(v);
          if (pk) { ownPubkey = pk; return true; }
        }
        return false;
      });
    });
    return {
      name: addr,
      description: addr,
      free: true,
      kind: "address",
      address: addr,
      isRoot: true,
      pubkey: ownPubkey,
      stats: {
        funded: data.total_received || 0,
        spent: data.total_sent || 0,
        balance: data.final_balance || 0,
        txCount: data.n_tx || txs.length
      },
      loadedTxCount: txs.length,
      children: buildTxChildren(addr, txs)
    };
  }

  // Build a ROOT node for a single transaction (when the user enters a TXID
  // instead of an address). Its children are every counterparty of the tx:
  // the sender addresses (inputs) first, then the recipient addresses (outputs).
  // Each child is a normal lazily-expandable address node, so the graph then
  // behaves exactly like an address analysis one level down.
  function buildTxRoot(tx) {
    var inputs = tx.inputs || [], outs = tx.out || [];
    var sumIn = 0, sumOut = 0;
    inputs.forEach(function (v) { if (v.prev_out) sumIn += v.prev_out.value || 0; });
    outs.forEach(function (o) { sumOut += o.value || 0; });
    var confirmed = (tx.block_height != null && tx.block_height > 0);

    var kids = [], hidden = 0;
    var seenIn = {};
    inputs.forEach(function (v) {
      if (!v.prev_out) return;
      var a = v.prev_out.addr; if (!a) return;              // coinbase / unparsable
      var pk = extractPubkey(v);
      if (seenIn[a]) {
        seenIn[a].value += v.prev_out.value || 0;
        if (pk && !seenIn[a].pubkey) seenIn[a].pubkey = pk;
        return;
      }
      var n = makeAddressNode(a, v.prev_out.value || 0, "sender", pk);
      seenIn[a] = n; kids.push(n);
    });
    var seenOut = {};
    outs.forEach(function (o) {
      var a = o.addr; if (!a) return;
      if (seenOut[a]) { seenOut[a].value += o.value || 0; return; }
      var n = makeAddressNode(a, o.value || 0, "recipient", null);
      seenOut[a] = n; kids.push(n);
    });
    if (kids.length > MAX_COUNTERPARTIES) { hidden = kids.length - MAX_COUNTERPARTIES; kids = kids.slice(0, MAX_COUNTERPARTIES); }

    return {
      name: tx.hash,
      description: "Transaction " + tx.hash,
      free: true,
      kind: "tx",
      isRoot: true,
      txid: tx.hash,
      sumIn: sumIn, sumOut: sumOut,
      fee: tx.fee,
      size: tx.size,
      confirmed: confirmed,
      blockHeight: confirmed ? tx.block_height : null,
      blockTime: tx.time,
      hiddenCount: hidden,
      children: kids
    };
  }

  // ---------- d3 node surgery for lazy expansion ----------
  // Build a real d3 hierarchy subtree from plain data and graft it under `parent`.
  function makeSubtree(data, parent) {
    var n = d3.hierarchy(data, function (x) { return x && x.children ? x.children : null; });
    var base = parent.depth + 1;
    n.each(function (x) { x.depth += base; });   // offset depths onto the parent
    n.parent = parent;
    return n;
  }

  // ---------- click behaviour ----------
  function handleNodeClick(d) {
    // In fullscreen, suppress the slide-in detail panel so it can't cover the
    // chart — clicking still expands/traces the graph. The panel is used in the
    // normal (in-page) layout, where it sits below the tree, not over it.
    if (!isFullscreen()) openPanel(d);             // details panel (skipped in fullscreen)
    var data = d.data || {};
    if (data.isRoot) return;                       // keep the whole graph visible

    // An un-loaded counterparty address → fetch its transactions on demand.
    if (data.kind === "address" && !d.children && !d._children && !d._loaded && !d._loading) {
      if (activeChain && activeChain.model === "account") accountLazyExpand(d);
      else lazyExpand(d);
      return;
    }
    // Expand/collapse IN PLACE — no page scroll, no viewport auto-pan — so a
    // click keeps the graph exactly where it is (the pinned flow box gives the
    // feedback that used to require scrolling down to the detail card).
    if (d.children) { toggle(d); update(d); return; }
    if (d._children) { toggle(d); update(d); return; }
  }

  function lazyExpand(d) {
    var addr = d.data.address;
    if (!addr) return;

    function graft(txs) {
      d.data.children = buildTxChildren(addr, txs);
      d.data.loadedTxCount = txs.length;
      var kids = d.data.children.map(function (cd) {
        var node = makeSubtree(cd, d);
        if (node.children) { node._children = node.children; node.children = null; } // collapse tx
        return node;
      });
      d.children = kids.length ? kids : null;
      d._children = null;
      d._loaded = true;
      d._loading = false;
      if (kids.length) {
        allSearchNodes = allSearchNodes.concat(
          d.descendants().filter(function (x) { return x.depth > 0 && x.data && x.data.name; })
        );
      }
      setStatus(kids.length ? "" : ("No further transactions for " + shorten(addr) + "."), "");
      update(d);
    }

    if (txCache[addr]) { graft(txCache[addr]); return; }
    d._loading = true;
    setStatus("Loading transactions for " + shorten(addr) + " …", "loading");
    fetchAddr(addr, TX_LIMIT)
      .then(function (data) { var txs = (data && data.txs) || []; txCache[addr] = txs; graft(txs); })
      .catch(function (e) {
        d._loading = false;
        setStatus(/rate/.test(e && e.message) ? "Both explorers are rate-limiting — wait a few seconds and click again." : "Couldn't load transactions for that address.", "error");
      });
  }

  // ---------- detail-box content ----------
  function pill(text, cls) { return '<span class="badge-pill ' + cls + '">' + esc(text) + '</span>'; }
  function mono(text) { return '<span class="aa-mono">' + esc(text) + '</span>'; }
  function copyBtn(text) { return '<button class="aa-copy" type="button" data-copy="' + esc(text) + '" title="Copy">copy</button>'; }
  function row(label, valueHtml) {
    return '<div class="aa-row">' +
      (label ? '<span class="aa-row-label">' + esc(label) + '</span>' : '') +
      '<span class="aa-row-value">' + valueHtml + '</span></div>';
  }
  function pkRow(label, pk, emptyText) {
    if (pk) return row(label, mono(pk.key) + copyBtn(pk.key) + ' <span class="aa-muted">(' + esc(pk.kind) + ')</span>');
    return row(label, '<span class="aa-muted">' + esc(emptyText) + '</span>');
  }

  // ---------- pinned flow box ----------
  // A compact yellow box pinned inside the graph. It shows the clicked node's
  // FULL address/txid plus the root→…→node path ("kahan se kahan"), so the user
  // sees the flow instantly without ever scrolling down to the detail card.
  function updateFlowBox(d) {
    var box = $("aa-flowbox");
    if (!box) return;
    var data = d.data || {};
    var isTx = data.kind === "tx";
    var kind = isTx ? (data.isRoot ? "Root transaction" : "Transaction")
                    : (data.isRoot ? "Root address" : "Address");
    var id = isTx ? data.txid : data.address;

    // Amount / direction line.
    var flow = "";
    if (isTx && data.isRoot) {
      flow = "total out " + formatBTC(data.sumOut) + (data.fee != null ? "  ·  fee " + formatBTC(data.fee) : "");
    } else if (isTx) {
      var sign = data.direction === "received" ? "+" : data.direction === "sent" ? "−" : "±";
      flow = data.direction + "  " + sign + formatBTC(Math.abs(data.net));
    } else if (data.isRoot && data.stats) {
      flow = "balance " + formatBTC(data.stats.balance);
    } else if (data.value != null) {
      flow = (data.role === "recipient" ? "received " : "sent ") + formatBTC(data.value);
    }

    // Path from the root down to this node — the "from → to" flow.
    var path = d.ancestors().reverse().map(function (a) {
      var ad = a.data || {};
      return esc(ad.kind === "tx" ? ("tx " + shorten(ad.txid, 6, 4)) : shorten(ad.address || ad.name, 8, 6));
    }).join(" → ");

    box.innerHTML =
      '<div class="aa-flow-kind">' + esc(kind) +
        (flow ? ' <span class="aa-flow-amt">· ' + esc(flow) + '</span>' : '') + '</div>' +
      '<div class="aa-flow-id aa-mono">' + esc(id || "") + copyBtn(id || "") + '</div>' +
      (path ? '<div class="aa-flow-path">' + path + '</div>' : '');
    box.classList.remove("aa-hidden");
    wireCopyButtons(box);
  }

  function renderPanelContent(d) {
    updateFlowBox(d);                              // keep the pinned flow box in sync
    var data = d.data || {};
    var isTx = data.kind === "tx";

    var titleEl = $("panel-title");
    if (titleEl) titleEl.textContent = isTx ? (data.isRoot ? "Transaction (root)" : "Transaction")
                                            : (data.isRoot ? "Address (root)" : "Address");

    // Breadcrumb — ancestor path (skip the node itself)
    var bc = $("panel-breadcrumb");
    if (bc) {
      var crumbs = d.ancestors().reverse().slice(0, -1).map(function (a) {
        var ad = a.data || {};
        return esc(ad.kind === "tx" ? ("tx " + shorten(ad.txid, 6, 4)) : shorten(ad.address || ad.name, 8, 6));
      });
      if (crumbs.length) { bc.innerHTML = crumbs.join(" › "); bc.classList.remove("empty"); }
      else { bc.textContent = ""; bc.classList.add("empty"); }
    }

    // Badges
    var badges = $("panel-badges");
    if (badges) {
      var b = "";
      if (isTx) {
        if (data.isRoot) {
          b += pill("Transaction", "badge-root");
        } else {
          b += pill(data.direction === "received" ? "Received" : data.direction === "sent" ? "Sent" : "Self-transfer",
                    "badge-" + data.direction);
        }
        b += " " + pill(data.confirmed ? "Confirmed" : "Pending", data.confirmed ? "badge-confirmed" : "badge-pending");
      } else if (data.isRoot) {
        b += pill("Root address", "badge-root");
      } else {
        b += pill(data.role === "sender" ? "Sender" : data.role === "recipient" ? "Recipient" : "Address", "badge-address");
      }
      badges.innerHTML = b;
      badges.classList.remove("empty");
    }

    // Summary
    var descSec = $("panel-description-section"), desc = $("panel-description");
    if (descSec && desc) {
      var s = "";
      if (isTx) {
        if (data.isRoot) {
          s = "Total out " + formatBTC(data.sumOut) + (data.fee != null ? "   ·   fee " + formatBTC(data.fee) : "");
        } else {
          var sign = data.direction === "received" ? "+" : data.direction === "sent" ? "−" : "±";
          s = sign + formatBTC(Math.abs(data.net)) + (data.fee != null ? "   ·   fee " + formatBTC(data.fee) : "");
        }
      } else if (data.isRoot && data.stats) {
        s = "Balance " + formatBTC(data.stats.balance) + "   ·   " + data.stats.txCount + " transaction(s)";
      } else if (data.value != null) {
        s = (data.role === "recipient" ? "Received " : "Sent ") + formatBTC(data.value) + " in this transaction";
      }
      desc.textContent = s;
      descSec.classList.remove("empty");
    }

    // Detail rows
    var detSec = $("panel-details-section"), det = $("panel-details");
    if (detSec && det) {
      var rows = [];
      if (isTx) {
        rows.push(row("TXID", mono(data.txid) + copyBtn(data.txid)));
        if (data.direction && !data.isRoot) rows.push(row("Direction", esc(data.direction)));
        if (data.sumIn) rows.push(row(data.isRoot ? "Total inputs" : "Spent from this address", formatBTC(data.sumIn)));
        if (data.sumOut) rows.push(row(data.isRoot ? "Total outputs" : "Received by this address", formatBTC(data.sumOut)));
        if (data.fee != null) rows.push(row("Fee", formatBTC(data.fee)));
        rows.push(row("Status", data.confirmed
          ? ("Confirmed" + (data.blockHeight ? " · block " + data.blockHeight : ""))
          : "Pending (in mempool)"));
        if (data.blockTime) rows.push(row("Time", new Date(data.blockTime * 1000).toUTCString()));
        if (!data.isRoot && activeChain && activeChain.showPubkey) rows.push(pkRow("Public key of spender", data.ownPubkey, "Not revealed in this transaction"));
      } else {
        rows.push(row("Address", mono(data.address) + copyBtn(data.address)));
        if (data.isRoot && data.stats) {
          rows.push(row("Balance", formatBTC(data.stats.balance)));
          if (activeChain && activeChain.model === "account") {
            if (data.stats.funded) rows.push(row("Total received", formatBTC(data.stats.funded)));
          } else {
            rows.push(row("Total received", formatBTC(data.stats.funded)));
            rows.push(row("Total sent", formatBTC(data.stats.spent)));
          }
          rows.push(row("Transactions", esc(String(data.stats.txCount)) +
            (data.loadedTxCount < data.stats.txCount ? " <span class='aa-muted'>(showing newest " + data.loadedTxCount + ")</span>" : "")));
        } else if (data.value != null) {
          rows.push(row(data.role === "recipient" ? "Amount received" : "Amount sent", formatBTC(data.value)));
        }
        if (activeChain && activeChain.showPubkey) rows.push(pkRow("Public key", data.pubkey, "Not revealed yet — appears only once this address spends"));
        if (!data.isRoot && !d._loaded) {
          rows.push(row("", "<span class='aa-muted'>Click this node to load its transactions.</span>"));
        }
      }
      det.innerHTML = rows.join("");
      detSec.classList.remove("empty");
      wireCopyButtons(det);
    }

    // CTA — open on the blockchain.info explorer
    var ctaSec = $("panel-cta-section"), cta = $("panel-open-tool");
    if (ctaSec && cta) {
      var ch = activeChain || CHAINS.bitcoin;
      cta.href = isTx
        ? (ch.explorerTx ? ch.explorerTx(data.txid) : "#")
        : (ch.explorerAddr ? ch.explorerAddr(data.address) : "#");
      cta.textContent = (isTx ? "View transaction" : "View address") + " on explorer ↗";
      ctaSec.classList.remove("empty");
    }
  }

  // Robust clipboard copy: prefer the async Clipboard API (needs a secure
  // context), fall back to a temporary <textarea> + execCommand where it is
  // unavailable or rejects. In fullscreen the temp element MUST be attached
  // inside the fullscreen subtree or it can't be focused/selected.
  function legacyCopy(text) {
    return new Promise(function (resolve, reject) {
      try {
        var host = document.fullscreenElement || document.webkitFullscreenElement || document.body;
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.top = "0";
        ta.style.left = "0";
        ta.style.width = "1px";
        ta.style.height = "1px";
        ta.style.padding = "0";
        ta.style.border = "none";
        ta.style.opacity = "0";
        host.appendChild(ta);
        ta.focus();
        ta.select();
        try { ta.setSelectionRange(0, text.length); } catch (e) {}
        var ok = document.execCommand("copy");
        host.removeChild(ta);
        ok ? resolve() : reject(new Error("execCommand copy rejected"));
      } catch (e) { reject(e); }
    });
  }
  function copyToClipboard(text) {
    text = String(text == null ? "" : text);
    if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
      return navigator.clipboard.writeText(text).catch(function () { return legacyCopy(text); });
    }
    return legacyCopy(text);
  }
  function flashCopyBtn(btn, msg) {
    if (!btn.getAttribute("data-label")) btn.setAttribute("data-label", btn.textContent);
    btn.textContent = msg;
    clearTimeout(btn._flashT);
    btn._flashT = setTimeout(function () { btn.textContent = btn.getAttribute("data-label"); }, 1300);
  }
  function wireCopyButtons(container) {
    container.querySelectorAll(".aa-copy").forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        e.stopPropagation();
        e.preventDefault();
        var text = btn.getAttribute("data-copy") || "";
        copyToClipboard(text).then(function () {
          flashCopyBtn(btn, "copied");
        }).catch(function () {
          flashCopyBtn(btn, "copy failed");
        });
      });
    });
  }

  // ---------- analyse flow ----------
  function hidePlaceholder() { var p = $("aa-placeholder"); if (p) p.classList.add("aa-hidden"); }
  function showSearch() { var s = $("search-container"); if (s) s.classList.remove("aa-hidden"); }

  // Populate the three summary stat cards. Labels adapt to what was analysed:
  // an address shows Balance / Received / TX; a transaction shows Out / In / Fee.
  // Spinner shown in the Balance / Received / TX boxes while a lookup is in flight —
  // the same rotating wheel the Public Key Toolkit / private-keys pages use. Own
  // class (.aa-spin) so the global icon-tint filters never recolour it; the tool
  // CSS tints + spins it.
  function spinner(size) {
    var n = size || 13;
    return '<img src="../assets/svgs/solid/spinner.svg" class="aa-spin" width="' + n +
      '" height="' + n + '" alt="loading">';
  }
  // Drop a spinner into the three summary boxes for the fetch/waiting window.
  function statLoading() {
    ["aa-stat-v1", "aa-stat-v2", "aa-stat-v3"].forEach(function (id) {
      var el = $(id);
      if (el) { el.innerHTML = spinner(16); el.classList.remove("has-balance"); }
    });
  }
  function toggleFunded(id, on) { var v = $(id); if (v) v.classList.toggle("has-balance", !!on); }

  function setStat(labelId, valueId, label, value) {
    var l = $(labelId), v = $(valueId);
    if (l) l.textContent = label;
    if (v) { v.textContent = value; v.classList.remove("has-balance"); }
  }
  function statsForAddress(stats) {
    setStat("aa-stat-l1", "aa-stat-v1", "Balance",  formatBTC(stats.balance));
    setStat("aa-stat-l2", "aa-stat-v2", "Received", formatBTC(stats.funded));
    setStat("aa-stat-l3", "aa-stat-v3", "TX",       String(stats.txCount));
    // Turn the amount green when the address holds (Balance) or has ever held
    // (Received) coins — matching the private-keys balance green (#22c55e).
    toggleFunded("aa-stat-v1", Number(stats.balance) > 0);
    toggleFunded("aa-stat-v2", Number(stats.funded) > 0);
  }
  function statsForTx(root) {
    setStat("aa-stat-l1", "aa-stat-v1", "Total Out", formatBTC(root.sumOut));
    setStat("aa-stat-l2", "aa-stat-v2", "Total In",  formatBTC(root.sumIn));
    setStat("aa-stat-l3", "aa-stat-v3", "Fee",       root.fee != null ? formatBTC(root.fee) : "—");
  }
  // Clear the summary boxes back to zero (used on error paths so the loading
  // spinner never keeps spinning if a lookup fails).
  function statsReset() {
    setStat("aa-stat-l1", "aa-stat-v1", "Balance",  formatBTC(0));
    setStat("aa-stat-l2", "aa-stat-v2", "Received", formatBTC(0));
    setStat("aa-stat-l3", "aa-stat-v3", "TX",       "0");
  }

  // Route the single input box for the active chain: a 64-hex TXID (bitcoin only)
  // → transaction analysis; anything that passes the chain's address validator
  // → address analysis; otherwise explain what this chain expects.
  function analyze(input) {
    input = (input || "").trim();
    var ch = currentChain();
    if (!input) {
      setStatus("Enter a " + ch.name + " address" + (ch.txid ? " or transaction ID" : "") + ".", "error");
      return;
    }
    if (ch.txid && isProbablyTxid(input)) { analyzeTx(input); return; }
    if (!ch.validate || ch.validate(input)) { analyzeAddress(input); return; }
    setStatus("That doesn't look like a valid " + ch.name + " address" +
              (ch.txid ? " or transaction ID" : "") + ". Please check and try again.", "error");
  }

  function analyzeAddress(addr) {
    var btn = $("analyze-btn");
    if (btn) btn.disabled = true;
    var done = function () { if (btn) btn.disabled = false; };
    setStatus("Fetching transactions for " + shorten(addr) + " …", "loading");
    statLoading();

    // ---- Account model: balance via BalanceChecker (reuse) + txs via adapter ----
    if (activeChain && activeChain.model === "account") {
      var statsP = getStats(activeChain, addr);
      var txP = (typeof activeChain.fetchTxs === "function")
        ? activeChain.fetchTxs(addr, TX_LIMIT).catch(function () { return null; })
        : Promise.resolve(null);
      Promise.all([statsP, txP])
        .then(function (res) {
          var stats = res[0] || {};
          var txs = res[1];
          var txUnavailable = (txs == null);
          txs = txs || [];
          txCache[addr] = txs;
          var rootData = buildAccountRoot(addr, txs, stats);
          hidePlaceholder();
          showSearch();
          window.renderGraph(rootData);
          if (window.root) updateFlowBox(window.root);
          statsForAddress(rootData.stats);
          if (txUnavailable) {
            setStatus("Balance loaded for " + shorten(addr) + ". A live transaction graph isn't available for " +
                      activeChain.name + " yet — showing balance and stats.", "");
          } else {
            setStatus(txs.length
              ? ("Loaded " + txs.length + " transaction(s)" +
                 (rootData.stats.txCount > txs.length ? " of " + rootData.stats.txCount + " (newest first)" : "") +
                 ". Click a transaction to expand it.")
              : "No transactions found for this address.", "");
          }
          try { history.replaceState(null, "", "?address=" + encodeURIComponent(addr)); } catch (e) {}
        })
        .catch(function () {
          statsReset();
          setStatus("Couldn't load data for that " + activeChain.name + " address. Check it and try again.", "error");
        })
        .then(done);
      return;
    }

    // ---- UTXO model: the explorer response carries BOTH stats and txs ----
    activeChain.fetchAddr(addr, TX_LIMIT)
      .then(function (data) {
        var txs = (data && data.txs) || [];
        txCache[addr] = txs;
        var rootData = buildRoot(addr, data);
        hidePlaceholder();
        showSearch();
        window.renderGraph(rootData);
        if (window.root) updateFlowBox(window.root);   // seed the pinned box with the root
        statsForAddress(rootData.stats);
        setStatus(txs.length
          ? ("Loaded " + txs.length + " transaction(s)" + (rootData.stats.txCount > txs.length ? " of " + rootData.stats.txCount + " (newest first)" : "") + (lastSource ? " · via " + lastSource : "") + ". Click a transaction to expand it.")
          : "No transactions found for this address.", "");
        try { history.replaceState(null, "", "?address=" + encodeURIComponent(addr)); } catch (e) {}
      })
      .catch(function (e) {
        // Explorer unavailable / not wired → still show balance + stats via the
        // keyless engine, with a clear "no tx graph" note. Never a dead tab.
        return getStats(activeChain, addr).then(function (stats) {
          var hasData = stats && (Number(stats.balance) > 0 || typeof stats.txCount === "number");
          if (!hasData) {
            statsReset();
            setStatus(/rate/.test(e && e.message)
              ? "Explorers are rate-limiting — wait a few seconds and press Analyze again."
              : "Couldn't reach the block explorer for " + activeChain.name + ". Check your connection and try again.", "error");
            return;
          }
          var rootData = buildAccountRoot(addr, [], stats);
          hidePlaceholder();
          showSearch();
          window.renderGraph(rootData);
          if (window.root) updateFlowBox(window.root);
          statsForAddress(rootData.stats);
          setStatus("Balance loaded for " + shorten(addr) + ". A live transaction graph isn't available for " +
                    activeChain.name + " right now — showing balance and stats.", "");
          try { history.replaceState(null, "", "?address=" + encodeURIComponent(addr)); } catch (e2) {}
        });
      })
      .then(done);
  }

  function analyzeTx(txid) {
    txid = txid.toLowerCase();
    var btn = $("analyze-btn");
    if (btn) btn.disabled = true;
    setStatus("Fetching transaction " + shorten(txid) + " …", "loading");
    statLoading();

    fetchTx(txid)
      .then(function (tx) {
        var rootData = buildTxRoot(tx);
        hidePlaceholder();
        showSearch();
        window.renderGraph(rootData);
        if (window.root) updateFlowBox(window.root);   // seed the pinned box with the root
        statsForTx(rootData);
        var parties = (rootData.children || []).length + (rootData.hiddenCount || 0);
        setStatus("Loaded transaction " + shorten(txid) + " · " + parties + " counterparty address(es)" +
                  (rootData.hiddenCount ? " (showing " + rootData.children.length + ")" : "") +
                  " · via " + lastSource + ". Click an address to trace its transactions.", "");
        try { history.replaceState(null, "", "?txid=" + encodeURIComponent(txid)); } catch (e) {}
      })
      .catch(function (e) {
        statsReset();
        setStatus(/rate/.test(e && e.message)
          ? "Both explorers are rate-limiting — wait a few seconds and press Analyze again."
          : "Couldn't find that transaction. Check the TXID and try again.", "error");
      })
      .then(function () { if (btn) btn.disabled = false; });
  }

  // Keep the tree's node colours in sync with the site's light/dark theme.
  // arf.js bakes each circle/text fill as a *resolved* hex (via getCSSVar) at
  // update() time, so those inline styles do NOT follow a later theme switch on
  // their own. Re-running update(root) makes the engine re-read the current
  // --cgt-* values and recolour every visible node. (Links use a live CSS var,
  // so they already follow the theme.)
  function watchTheme() {
    var html = document.documentElement;
    var last = html.getAttribute("data-bs-theme");
    var obs = new MutationObserver(function () {
      var now = html.getAttribute("data-bs-theme");
      if (now === last) return;
      last = now;
      if (window.root && typeof window.update === "function") window.update(window.root);
    });
    obs.observe(html, { attributes: true, attributeFilter: ["data-bs-theme"] });
  }

  // ============================================================================
  // ACCOUNT MODEL (EVM ×8, Tron, XRP, TON, Sui, Solana)
  // ----------------------------------------------------------------------------
  // Account-based chains have no UTXO inputs/outputs — each transfer is a single
  // from → to with one amount. We normalise every provider response into:
  //   { hash, from, to, value, time, blockHeight, fee, token }   (value = smallest unit)
  // and build tree nodes shaped like the UTXO ones so arf.js + the detail
  // panel + flow box (which are chain-agnostic) render them unchanged.
  // ============================================================================

  function eq(a, b) { return a && b && String(a).toLowerCase() === String(b).toLowerCase(); }

  // One transaction as seen FROM the context address: its single child is the
  // counterparty (the other side of the transfer), lazily expandable.
  function makeAccountTxNode(tx, ctxAddr) {
    var isOut = eq(tx.from, ctxAddr);
    var isIn = eq(tx.to, ctxAddr);
    var direction = (isOut && isIn) ? "self" : isOut ? "sent" : "received";
    var counterparty = direction === "sent" ? tx.to : tx.from;
    var value = tx.value || 0;
    var net = direction === "received" ? value : direction === "sent" ? -value : 0;

    var cps = [];
    if (counterparty && !eq(counterparty, ctxAddr)) {
      cps.push(makeAccountAddressNode(counterparty, value,
               direction === "sent" ? "recipient" : "sender"));
    }

    var confirmed = (tx.blockHeight != null && tx.blockHeight > 0);
    var sign = direction === "received" ? "+" : direction === "sent" ? "−" : "±";
    var amt = formatValue(Math.abs(net) || value, activeChain);
    var label = (tx.token ? tx.token + " " : "") + amt;
    return {
      name: tx.hash + "   " + sign + label,
      description: "Transaction " + tx.hash + " — " + direction + " " + sign + label,
      free: true,
      kind: "tx",
      txid: tx.hash,
      direction: direction,
      dir: direction === "received" ? "in" : direction === "sent" ? "out" : "self",
      net: net,
      fee: tx.fee,
      token: tx.token || null,
      confirmed: confirmed,
      blockHeight: confirmed ? tx.blockHeight : null,
      blockTime: tx.time,
      contextAddress: ctxAddr,
      children: cps
    };
  }

  // A counterparty address node — lazily loads its own transactions on click.
  function makeAccountAddressNode(addr, value, role) {
    var sign = role === "recipient" ? "−" : "+";
    return {
      name: addr + "   " + sign + formatValue(value, activeChain),
      description: addr + " — click to trace its transactions",
      free: true,
      kind: "address",
      address: addr,
      value: value,
      role: role,
      dir: role === "recipient" ? "out" : "in",
      children: null
    };
  }

  // Root node for an account address: children are its transactions.
  function buildAccountRoot(addr, txs, stats) {
    return {
      name: addr,
      description: addr,
      free: true,
      kind: "address",
      address: addr,
      isRoot: true,
      stats: {
        funded: (stats && stats.received) || 0,
        spent: 0,
        balance: (stats && stats.balance) || 0,
        txCount: (stats && stats.txCount != null) ? stats.txCount : txs.length
      },
      loadedTxCount: txs.length,
      children: txs.map(function (tx) { return makeAccountTxNode(tx, addr); })
    };
  }

  // Lazy-expand an account counterparty address (mirrors the UTXO lazyExpand).
  function accountLazyExpand(d) {
    var addr = d.data.address;
    if (!addr || !activeChain || typeof activeChain.fetchTxs !== "function") return;

    function graft(txs) {
      d.data.children = txs.map(function (tx) { return makeAccountTxNode(tx, addr); });
      d.data.loadedTxCount = txs.length;
      var kids = d.data.children.map(function (cd) {
        var node = makeSubtree(cd, d);
        if (node.children) { node._children = node.children; node.children = null; }
        return node;
      });
      d.children = kids.length ? kids : null;
      d._children = null;
      d._loaded = true;
      d._loading = false;
      if (kids.length) {
        allSearchNodes = allSearchNodes.concat(
          d.descendants().filter(function (x) { return x.depth > 0 && x.data && x.data.name; })
        );
      }
      setStatus(kids.length ? "" : ("No further transactions for " + shorten(addr) + "."), "");
      update(d);
    }

    if (txCache[addr]) { graft(txCache[addr]); return; }
    d._loading = true;
    setStatus("Loading transactions for " + shorten(addr) + " …", "loading");
    activeChain.fetchTxs(addr, TX_LIMIT)
      .then(function (txs) { txs = txs || []; txCache[addr] = txs; graft(txs); })
      .catch(function () {
        d._loading = false;
        setStatus("Couldn't load transactions for that address.", "error");
      });
  }

  // ============================================================================
  // CHAIN REGISTRY + shared stats/validation/explorer helpers
  // ----------------------------------------------------------------------------
  // Every tab is one CHAINS entry keyed by its data-chain slug. Balance + stats
  // come from the site's existing keyless engine (window.BalanceChecker) for ALL
  // chains; the transaction graph comes from each chain's own fetcher:
  //   • UTXO chains   → fetchAddr(addr, limit)  → BCI-normalised {…, txs:[…]}
  //   • account chains→ fetchTxs(addr, limit)   → [{hash,from,to,value,time,…}]
  // A chain with no wired tx source degrades to balance-only (never "coming soon").
  // ============================================================================

  // ---- balance/stats via BalanceChecker (reuse; no keys, CORS-enabled) ----
  // Maps a chain's `type` to the engine's public batch fetcher. EVM chains all
  // share fetchEvmBalancesBatch(addresses, chainKey); others have a named fetcher.
  function balanceFetcherFor(chain) {
    var BC = window.BalanceChecker;
    if (!BC) return null;
    if (chain.type === "evm") {
      if (typeof BC.fetchEvmBalancesBatch !== "function") return null;
      return function (addrs) { return BC.fetchEvmBalancesBatch(addrs, chain.key); };
    }
    var byType = {
      bitcoin: "fetchBitcoinBalancesBatch", bitcoincash: "fetchBitcoinCashBalancesBatch",
      litecoin: "fetchLitecoinBalancesBatch", dogecoin: "fetchDogecoinBalancesBatch",
      zcash: "fetchZcashBalancesBatch", solana: "fetchSolanaBalancesBatch",
      tron: "fetchTronBalancesBatch", ton: "fetchTonBalancesBatch",
      sui: "fetchSuiBalancesBatch", xrp: "fetchXrpBalancesBatch"
    };
    var fn = byType[chain.type];
    if (!fn || typeof BC[fn] !== "function") return null;
    return function (addrs) { return BC[fn](addrs); };
  }

  // Convert a BalanceChecker value to a smallest-unit Number (for formatValue).
  // Prefer the BigInt `balance` (already smallest-unit); else human string ×10^dec.
  function toSmallest(big, humanStr, dec) {
    if (big != null) { var n = Number(big); if (!isNaN(n)) return n; }
    if (humanStr != null) { var h = parseFloat(humanStr); if (!isNaN(h)) return Math.round(h * Math.pow(10, dec)); }
    return 0;
  }

  // Fetch { balance, received, txCount } in smallest units for one address.
  // txCount is trusted only where the engine reports a real count (UTXO + Tron);
  // account chains derive it from the tx list, so we return null there.
  function getStats(chain, addr) {
    var fetcher = balanceFetcherFor(chain);
    if (!fetcher) return Promise.resolve({ balance: 0, received: 0, txCount: null });
    return fetcher([addr]).then(function (map) {
      var e = null;
      if (map && typeof map.get === "function") {
        e = map.get(addr);
        // Tolerate address normalisation (EVM checksum, cashaddr prefix, …): if the
        // engine keyed the result under a canonical form, take the sole entry.
        if (!e && map.size === 1) { map.forEach(function (v) { e = v; }); }
      } else if (map) { e = map[addr]; }
      if (!e) return { balance: 0, received: 0, txCount: 0 };
      var dec = chain.decimals != null ? chain.decimals : 8;
      return {
        balance: toSmallest(e.balance, e.balanceStr, dec),
        received: toSmallest(e.received, e.receivedStr, dec),
        txCount: (chain.trustTxCount && typeof e.txCount === "number") ? e.txCount : null,
        symbol: e.symbol
      };
    }).catch(function () { return { balance: 0, received: 0, txCount: null }; });
  }

  // ---- per-chain address validators (no shared validator exists in the site) ----
  var RE = {
    evm:      /^0x[0-9a-fA-F]{40}$/,
    tron:     /^T[1-9A-HJ-NP-Za-km-z]{33}$/,
    xrp:      /^r[1-9A-HJ-NP-Za-km-z]{23,34}$/,
    solana:   /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
    ton:      /^([A-Za-z0-9_-]{48}|(?:-1|0):[0-9a-fA-F]{64})$/,
    sui:      /^0x[0-9a-fA-F]{1,64}$/,
    litecoin: /^(ltc1[ac-hj-np-z02-9]{6,90}|[LM3][a-km-zA-HJ-NP-Z1-9]{25,39})$/,
    bch:      /^((bitcoincash:)?[qp][a-z0-9]{41}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$/,
    dogecoin: /^[DA9][a-km-zA-HJ-NP-Z1-9]{25,39}$/,
    zcash:    /^t[13][a-km-zA-HJ-NP-Z1-9]{33}$/
  };
  function reValidator(key) { return function (a) { return RE[key].test((a || "").trim()); }; }

  // ---- explorer URL builders ----
  function expl(base) { return function (x) { return base + encodeURIComponent(x || ""); }; }

  // ---- UTXO tx source: Esplora clone at an arbitrary base (litecoinspace etc.) ----
  // Reuses esploraTxToBci so buildRoot/buildTxChildren/lazyExpand work unchanged.
  function esploraBase(base) {
    return function (addr, limit) {
      var b = base + "/address/" + encodeURIComponent(addr);
      return Promise.all([ fetch(b).then(okJson), fetch(b + "/txs").then(okJson) ])
        .then(function (res) {
          var stats = res[0] || {}, rawTxs = res[1] || [];
          var cs = stats.chain_stats || {}, ms = stats.mempool_stats || {};
          var funded = (cs.funded_txo_sum || 0) + (ms.funded_txo_sum || 0);
          var spent = (cs.spent_txo_sum || 0) + (ms.spent_txo_sum || 0);
          return {
            address: addr,
            n_tx: ((cs.tx_count || 0) + (ms.tx_count || 0)) || rawTxs.length,
            total_received: funded, total_sent: spent, final_balance: funded - spent,
            txs: rawTxs.slice(0, limit || TX_LIMIT).map(esploraTxToBci),
            source: base.replace(/^https?:\/\//, "").replace(/\/api.*$/, "")
          };
        });
    };
  }
  // Wrap a UTXO fetcher so it records which explorer served the data (status line).
  function utxoVia(fn) {
    return function (addr, limit) {
      return fn(addr, limit).then(function (d) { lastSource = (d && d.source) || ""; return d; });
    };
  }

  // Placeholder for chains whose keyless tx source is not wired yet. Rejecting
  // here routes the flow to the balance-only fallback (never a dead tab).
  function notWired() { return Promise.reject(new Error("tx source not wired")); }

  // ============================================================================
  // TRANSACTION FETCHERS (keyless, CORS — verified endpoints)
  // Account fetchers resolve to [{hash, from, to, value, time, blockHeight, fee, token}]
  // (value/fee in smallest units); UTXO fetchers resolve to the BCI-normalised
  // {address, n_tx, total_received, total_sent, final_balance, txs:[…]} shape.
  // ============================================================================

  // ---- EVM: Blockscout API v2 (eth/base/optimism/arbitrum/polygon/zksync) ----
  // Same schema on every host: items[] with from.hash / to.hash / value(wei).
  function blockscoutTxs(host) {
    return function (addr, limit) {
      var url = "https://" + host + "/api/v2/addresses/" + encodeURIComponent(addr) + "/transactions";
      return fetch(url, { headers: { "Accept": "application/json" } }).then(okJson).then(function (d) {
        var items = (d && Array.isArray(d.items)) ? d.items : [];
        return items.slice(0, limit || TX_LIMIT).map(function (t) {
          return {
            hash: t.hash,
            from: (t.from && t.from.hash) || null,
            to: (t.to && t.to.hash) || null,
            value: Number(t.value || 0),                                 // wei
            time: t.timestamp ? Math.floor(Date.parse(t.timestamp) / 1000) : null,
            blockHeight: (t.block_number != null) ? Number(t.block_number) : null,
            fee: (t.fee && t.fee.value != null) ? Number(t.fee.value) : null
          };
        });
      });
    };
  }

  // ---- EVM: Routescan Etherscan-compatible API (Avalanche = chainId 43114) ----
  function routescanTxs(chainId) {
    return function (addr, limit) {
      var n = limit || TX_LIMIT;
      var url = "https://api.routescan.io/v2/network/mainnet/evm/" + chainId +
                "/etherscan/api?module=account&action=txlist&address=" + encodeURIComponent(addr) +
                "&sort=desc&page=1&offset=" + n;
      return fetch(url).then(okJson).then(function (d) {
        var list = (d && Array.isArray(d.result)) ? d.result : [];
        return list.slice(0, n).map(function (t) {
          return {
            hash: t.hash,
            from: t.from || null,
            to: t.to || null,
            value: Number(t.value || 0),
            time: t.timeStamp ? Number(t.timeStamp) : null,
            blockHeight: t.blockNumber ? Number(t.blockNumber) : null,
            fee: (t.gasUsed && t.gasPrice) ? Number(t.gasUsed) * Number(t.gasPrice) : null
          };
        });
      });
    };
  }

  // ---- Tron: tronscan (clean base58 from/to/amount; TRC-20 in trigger_info) ----
  function tronscanTxs() {
    return function (addr, limit) {
      var n = limit || TX_LIMIT;
      var url = "https://apilist.tronscanapi.com/api/transaction?address=" + encodeURIComponent(addr) +
                "&limit=" + n + "&start=0";
      return fetch(url).then(okJson).then(function (d) {
        var list = (d && Array.isArray(d.data)) ? d.data : [];
        return list.slice(0, n).map(function (t) {
          var ti = t.tokenInfo || {};
          var to = t.toAddress, value = Number(t.amount || 0), token = null;
          // TRC-20 transfers carry amount "0" at the top level; the real recipient
          // + value live in trigger_info.parameter (USDT-TRON is 6-decimals, ~= TRX).
          if ((t.amount === "0" || t.amount === 0) && t.trigger_info && t.trigger_info.parameter) {
            var p = t.trigger_info.parameter;
            if (p._to) to = p._to;
            if (p._value != null) value = Number(p._value);
            token = (ti.tokenAbbr || "TRC20").toUpperCase();
          }
          return {
            hash: t.hash,
            from: t.ownerAddress || null,
            to: to || null,
            value: value,
            time: t.timestamp ? Math.floor(Number(t.timestamp) / 1000) : null,
            blockHeight: t.block ? Number(t.block) : null,
            fee: null,
            token: token
          };
        });
      });
    };
  }

  // ---- XRP: xrpscan (Payments; Amount is a drops string, or an issued-token obj) ----
  function xrpscanTxs() {
    return function (addr, limit) {
      var n = limit || TX_LIMIT;
      var url = "https://api.xrpscan.com/api/v1/account/" + encodeURIComponent(addr) + "/transactions?limit=" + n;
      return fetch(url).then(okJson).then(function (d) {
        var list = (d && Array.isArray(d.transactions)) ? d.transactions : [];
        return list.slice(0, n).filter(function (t) {
          return t && (t.TransactionType === "Payment" || t.Amount != null);
        }).map(function (t) {
          var value = 0, token = null;
          if (typeof t.Amount === "string") value = Number(t.Amount);          // drops
          else if (t.Amount && t.Amount.value != null) { value = Number(t.Amount.value); token = t.Amount.currency; }
          return {
            hash: t.hash,
            from: t.Account || null,
            to: t.Destination || null,
            value: value,
            time: t.date ? Math.floor(Date.parse(t.date) / 1000) : null,
            blockHeight: (t.ledger_index != null) ? Number(t.ledger_index) : null,
            fee: (t.Fee != null) ? Number(t.Fee) : null,
            token: token
          };
        });
      });
    };
  }

  // ---- TON: tonapi events (TonTransfer / JettonTransfer actions, nested) ----
  function tonapiTxs() {
    return function (addr, limit) {
      var n = limit || TX_LIMIT;
      var url = "https://tonapi.io/v2/accounts/" + encodeURIComponent(addr) + "/events?limit=" + n;
      return fetch(url).then(okJson).then(function (d) {
        var events = (d && Array.isArray(d.events)) ? d.events : [];
        var out = [];
        events.forEach(function (ev) {
          var actions = (ev && Array.isArray(ev.actions)) ? ev.actions : [];
          for (var i = 0; i < actions.length; i++) {
            var tt = actions[i].TonTransfer, jt = actions[i].JettonTransfer;
            if (tt) {
              out.push({ hash: ev.event_id,
                from: tt.sender && tt.sender.address, to: tt.recipient && tt.recipient.address,
                value: Number(tt.amount || 0), time: ev.timestamp ? Number(ev.timestamp) : null,
                blockHeight: null, fee: null, token: null });
              break;
            } else if (jt) {
              out.push({ hash: ev.event_id,
                from: jt.sender && jt.sender.address, to: jt.recipient && jt.recipient.address,
                value: Number(jt.amount || 0), time: ev.timestamp ? Number(ev.timestamp) : null,
                blockHeight: null, fee: null,
                token: (jt.jetton && (jt.jetton.symbol || jt.jetton.name)) || "Jetton" });
              break;
            }
          }
        });
        return out.slice(0, n);
      });
    };
  }

  // ---- UTXO: BlockCypher /full (Dogecoin) → BCI shape (stats + full txs) ----
  function blockcypherUtxo(coin) {
    return function (addr, limit) {
      var n = limit || TX_LIMIT;
      var url = "https://api.blockcypher.com/v1/" + coin + "/main/addrs/" + encodeURIComponent(addr) + "/full?limit=" + n;
      return fetch(url).then(okJson).then(function (d) {
        var txs = (d && Array.isArray(d.txs)) ? d.txs : [];
        return {
          address: (d && d.address) || addr,
          n_tx: (d && d.n_tx != null) ? d.n_tx : txs.length,
          total_received: (d && d.total_received) || 0,
          total_sent: (d && d.total_sent) || 0,
          final_balance: (d && (d.final_balance != null ? d.final_balance : d.balance)) || 0,
          txs: txs.slice(0, n).map(function (t) {
            return {
              hash: t.hash,
              time: t.confirmed ? Math.floor(Date.parse(t.confirmed) / 1000) : null,
              block_height: (t.block_height && t.block_height > 0) ? t.block_height : null,
              fee: t.fees,
              inputs: (t.inputs || []).map(function (v) {
                return { prev_out: { addr: (v.addresses && v.addresses[0]) || null, value: v.output_value || 0 }, script: "" };
              }),
              out: (t.outputs || []).map(function (o) {
                return { addr: (o.addresses && o.addresses[0]) || null, value: o.value || 0 };
              })
            };
          }),
          source: "blockcypher.com"
        };
      });
    };
  }

  // ---- UTXO: Haskoin (Bitcoin Cash) → BCI shape ----
  // Haskoin (api.haskoin.com) is keyless and sends Access-Control-Allow-Origin:*,
  // so it is browser-callable. It has no aggregate-stats field on the tx list, so
  // we pair /balance (confirmed/received/txs) with /transactions/full (the txs).
  // If the coin's shard is unavailable (it 502s at times), the fetch rejects and
  // analyzeAddress falls back to balance-only — so BCH is never a dead tab.
  function haskoinUtxo(coin) {
    return function (addr, limit) {
      var n = limit || TX_LIMIT;
      var base = "https://api.haskoin.com/" + coin + "/address/" + encodeURIComponent(addr);
      return Promise.all([
        fetch(base + "/balance").then(okJson),
        fetch(base + "/transactions/full?limit=" + n).then(okJson)
      ]).then(function (res) {
        var b = res[0] || {}, list = Array.isArray(res[1]) ? res[1] : [];
        var balance = Number(b.confirmed || 0) + Number(b.unconfirmed || 0);
        var received = Number(b.received || 0);
        return {
          address: b.address || addr,
          n_tx: (b.txs != null) ? Number(b.txs) : list.length,
          total_received: received,
          total_sent: Math.max(0, received - balance),
          final_balance: balance,
          txs: list.slice(0, n).map(function (t) {
            return {
              hash: t.txid,
              time: t.time || null,
              block_height: (t.block && t.block.height > 0) ? t.block.height : null,
              fee: (t.fee != null) ? Number(t.fee) : null,
              inputs: (t.inputs || []).map(function (v) {
                return { prev_out: { addr: v.address || null, value: Number(v.value || 0) }, script: "" };
              }),
              out: (t.outputs || []).map(function (o) {
                return { addr: o.address || null, value: Number(o.value || 0) };
              })
            };
          }),
          source: "haskoin.com"
        };
      });
    };
  }

  // ---- the registry: 18 chains keyed by data-chain slug ----
  var CHAINS = {
    bitcoin: {
      name: "Bitcoin", symbol: "BTC", decimals: 8, model: "utxo", type: "bitcoin",
      validate: isProbablyBtcAddress, fetchAddr: fetchAddr,
      explorerAddr: expl("https://www.blockchain.com/explorer/addresses/btc/"),
      explorerTx:   expl("https://www.blockchain.com/explorer/transactions/btc/"),
      showPubkey: true, txid: true, trustTxCount: true
    },
    litecoin: {
      name: "Litecoin", symbol: "LTC", decimals: 8, model: "utxo", type: "litecoin",
      validate: reValidator("litecoin"), fetchAddr: utxoVia(esploraBase("https://litecoinspace.org/api")),
      explorerAddr: expl("https://blockchair.com/litecoin/address/"),
      explorerTx:   expl("https://blockchair.com/litecoin/transaction/"),
      trustTxCount: true
    },
    "bitcoin-cash": {
      name: "Bitcoin Cash", symbol: "BCH", decimals: 8, model: "utxo", type: "bitcoincash",
      validate: reValidator("bch"), fetchAddr: utxoVia(haskoinUtxo("bch")),
      explorerAddr: expl("https://blockchair.com/bitcoin-cash/address/"),
      explorerTx:   expl("https://blockchair.com/bitcoin-cash/transaction/"),
      trustTxCount: true
    },
    dogecoin: {
      name: "Dogecoin", symbol: "DOGE", decimals: 8, model: "utxo", type: "dogecoin",
      validate: reValidator("dogecoin"), fetchAddr: utxoVia(blockcypherUtxo("doge")),
      explorerAddr: expl("https://blockchair.com/dogecoin/address/"),
      explorerTx:   expl("https://blockchair.com/dogecoin/transaction/"),
      trustTxCount: true
    },
    zcash: {
      name: "Zcash", symbol: "ZEC", decimals: 8, model: "utxo", type: "zcash",
      validate: reValidator("zcash"), fetchAddr: notWired,   // no keyless CORS Zcash tx API → balance-only
      explorerAddr: expl("https://blockchair.com/zcash/address/"),
      explorerTx:   expl("https://blockchair.com/zcash/transaction/"),
      trustTxCount: true
    },
    ethereum: {
      name: "Ethereum", symbol: "ETH", decimals: 18, model: "account", type: "evm", key: "ethereum",
      validate: reValidator("evm"), fetchTxs: blockscoutTxs("eth.blockscout.com"),
      explorerAddr: expl("https://etherscan.io/address/"), explorerTx: expl("https://etherscan.io/tx/")
    },
    bnb: {
      name: "BNB Chain", symbol: "BNB", decimals: 18, model: "account", type: "evm", key: "bnb",
      validate: reValidator("evm"), fetchTxs: notWired,
      explorerAddr: expl("https://bscscan.com/address/"), explorerTx: expl("https://bscscan.com/tx/")
    },
    arbitrum: {
      name: "Arbitrum", symbol: "ETH", decimals: 18, model: "account", type: "evm", key: "arbitrum",
      validate: reValidator("evm"), fetchTxs: blockscoutTxs("arbitrum.blockscout.com"),
      explorerAddr: expl("https://arbiscan.io/address/"), explorerTx: expl("https://arbiscan.io/tx/")
    },
    optimism: {
      name: "Optimism", symbol: "ETH", decimals: 18, model: "account", type: "evm", key: "optimism",
      validate: reValidator("evm"), fetchTxs: blockscoutTxs("explorer.optimism.io"),
      explorerAddr: expl("https://optimistic.etherscan.io/address/"), explorerTx: expl("https://optimistic.etherscan.io/tx/")
    },
    base: {
      name: "Base", symbol: "ETH", decimals: 18, model: "account", type: "evm", key: "base",
      validate: reValidator("evm"), fetchTxs: blockscoutTxs("base.blockscout.com"),
      explorerAddr: expl("https://basescan.org/address/"), explorerTx: expl("https://basescan.org/tx/")
    },
    polygon: {
      name: "Polygon", symbol: "POL", decimals: 18, model: "account", type: "evm", key: "polygon",
      validate: reValidator("evm"), fetchTxs: blockscoutTxs("polygon.blockscout.com"),
      explorerAddr: expl("https://polygonscan.com/address/"), explorerTx: expl("https://polygonscan.com/tx/")
    },
    avalanche: {
      name: "Avalanche", symbol: "AVAX", decimals: 18, model: "account", type: "evm", key: "avalanche",
      validate: reValidator("evm"), fetchTxs: routescanTxs(43114),
      explorerAddr: expl("https://snowtrace.io/address/"), explorerTx: expl("https://snowtrace.io/tx/")
    },
    zksync: {
      name: "zkSync Era", symbol: "ETH", decimals: 18, model: "account", type: "evm", key: "zksync",
      validate: reValidator("evm"), fetchTxs: blockscoutTxs("zksync.blockscout.com"),
      explorerAddr: expl("https://explorer.zksync.io/address/"), explorerTx: expl("https://explorer.zksync.io/tx/")
    },
    tron: {
      name: "Tron", symbol: "TRX", decimals: 6, model: "account", type: "tron",
      validate: reValidator("tron"), fetchTxs: tronscanTxs(), trustTxCount: true,
      explorerAddr: expl("https://tronscan.org/#/address/"), explorerTx: expl("https://tronscan.org/#/transaction/")
    },
    xrp: {
      name: "XRP", symbol: "XRP", decimals: 6, model: "account", type: "xrp",
      validate: reValidator("xrp"), fetchTxs: xrpscanTxs(),
      explorerAddr: expl("https://xrpscan.com/account/"), explorerTx: expl("https://xrpscan.com/tx/")
    },
    toncoin: {
      name: "TON", symbol: "TON", decimals: 9, model: "account", type: "ton",
      validate: reValidator("ton"), fetchTxs: tonapiTxs(),
      explorerAddr: expl("https://tonviewer.com/"), explorerTx: expl("https://tonviewer.com/transaction/")
    },
    sui: {
      name: "Sui", symbol: "SUI", decimals: 9, model: "account", type: "sui",
      validate: reValidator("sui"), fetchTxs: notWired,
      explorerAddr: expl("https://suiscan.xyz/mainnet/account/"), explorerTx: expl("https://suiscan.xyz/mainnet/tx/")
    },
    solana: {
      name: "Solana", symbol: "SOL", decimals: 9, model: "account", type: "solana",
      validate: reValidator("solana"), fetchTxs: notWired,
      explorerAddr: expl("https://solscan.io/account/"), explorerTx: expl("https://solscan.io/tx/")
    }
  };

  // ---------- chain selector ----------
  function currentChain() { return activeChain || CHAINS.bitcoin; }

  // Update the search bar (icon, placeholder, hint), stat-card symbols and the
  // empty-canvas placeholder to reflect the chosen chain.
  function applyChainUi(slug, tabEl) {
    var chain = CHAINS[slug];
    if (!chain) return;
    var icon = $("aa-search-icon");
    var tabImg = tabEl ? tabEl.querySelector("img") : null;
    if (icon && tabImg) { icon.src = tabImg.src; icon.alt = tabImg.alt || slug; }

    var ph = chain.txid ? (chain.name + " address or transaction ID (TXID)") : (chain.name + " address");
    var input = $("address-input");
    if (input) { input.placeholder = ph; input.setAttribute("aria-label", ph); }
    var hint = $("aa-search-hint");
    if (hint) hint.textContent = "Enter a " + chain.name + " address" +
      (chain.txid ? " or a 64-character transaction ID (TXID)." : ".") +
      " Balance and stats load for every chain; the transaction graph loads where a keyless explorer is available.";
    var title = document.querySelector(".aa-placeholder-title");
    if (title) title.textContent = "Explore a " + chain.name + (chain.txid ? " address or transaction" : " address");

    setStat("aa-stat-l1", "aa-stat-v1", "Balance",  "0 " + chain.symbol);
    setStat("aa-stat-l2", "aa-stat-v2", "Received", "0 " + chain.symbol);
    setStat("aa-stat-l3", "aa-stat-v3", "TX",       "0");
  }

  // Clear the graph/panel/flow box/status so the previous chain's view is gone.
  function resetForChain() {
    txCache = {};
    if (typeof closePanel === "function") closePanel();
    if (typeof vis !== "undefined" && vis) vis.selectAll("*").remove();
    var flow = $("aa-flowbox"); if (flow) { flow.classList.add("aa-hidden"); flow.innerHTML = ""; }
    var placeholder = $("aa-placeholder"); if (placeholder) placeholder.classList.remove("aa-hidden");
    var sc = $("search-container"); if (sc) sc.classList.add("aa-hidden");
    setStatus("", "");
  }

  function selectChain(slug, tabEl) {
    var chain = CHAINS[slug];
    if (!chain) { setStatus("This chain isn't available.", "error"); return; }
    activeChain = chain;
    var tabs = document.querySelectorAll("#aa-chain-tabs .chain-tab");
    tabs.forEach(function (t) { t.classList.toggle("active", t === tabEl); });
    // Accent (CTA, flow box, active tab) follows the chain's own colour.
    var color = tabEl ? (tabEl.style.getPropertyValue("--chain-color") || "").trim() : "";
    document.documentElement.style.setProperty("--aa-accent", color || "#f7931a");
    applyChainUi(slug, tabEl);
    resetForChain();
    var input = $("address-input");
    if (input) { input.value = ""; input.focus(); }
  }

  // All coins are analysable. Clicking a tab switches the active chain.
  function wireChainTabs() {
    var tabs = document.querySelectorAll("#aa-chain-tabs .chain-tab");
    if (!tabs.length) return;
    tabs.forEach(function (tab) {
      var slug = tab.getAttribute("data-chain");
      tab.addEventListener("click", function (e) {
        e.preventDefault();
        selectChain(slug, tab);
      });
    });
  }

  // How many transactions to fetch per address. Reads the #aa-tx-limit selector
  // (100/200/300/500) and keeps TX_LIMIT in sync so BOTH Analyze and every address
  // you click in the graph fetch the chosen count. Changing it clears the
  // per-address cache so subsequent fetches use the new count.
  function wireTxLimit() {
    var sel = $("aa-tx-limit");
    if (!sel) return;
    function apply() {
      var n = parseInt(sel.value, 10);
      if (n > 0) { TX_LIMIT = n; txCache = {}; }
    }
    apply();                                   // honour the pre-selected value on load
    sel.addEventListener("change", apply);
  }

  // ---------- match list (trace highlight) ----------
  // A user-supplied list of addresses/TXIDs (one per line) kept highlighted in
  // YELLOW across the WHOLE graph — including nodes revealed later by expansion —
  // so a target can be traced as you walk tx → address → tx. arf.js asks
  // window.isWatched(d) for every node at render time, so newly-expanded nodes
  // light up automatically without re-walking the tree.
  var watchSet = {}, watchCount = 0;
  function parseWatchList(text) {
    var set = {}, n = 0;
    String(text || "").split(/[\s,;]+/).forEach(function (tok) {
      tok = tok.trim().toLowerCase();
      if (tok && !set[tok]) { set[tok] = 1; n++; }
    });
    watchCount = n;
    return set;
  }
  // Exact (case-insensitive) match on a node's full address OR full TXID.
  window.isWatched = function (d) {
    if (!d || !d.data) return false;
    var id = (d.data.kind === "tx") ? d.data.txid : d.data.address;
    return !!(id && watchSet[String(id).toLowerCase()]);
  };
  function updateWatchCount() {
    var el = $("aa-watch-count");
    if (el) el.textContent = String(watchCount);
  }
  function wireWatchList() {
    var box = $("aa-watchlist");
    if (!box) return;
    var t = null;
    function apply() {
      watchSet = parseWatchList(box.value);
      updateWatchCount();
      if (window.root && typeof update === "function") update(window.root);   // re-render → matches turn yellow
    }
    box.addEventListener("input", function () { clearTimeout(t); t = setTimeout(apply, 200); });
  }

  // ---------- fullscreen ----------
  // Expand the tree stage (#aa-stage) to fill the screen so large graphs can be
  // traced comfortably. The filter and match list live inside the stage so they
  // keep working; the detail panel is intentionally suppressed in fullscreen
  // (see handleNodeClick) so it never covers the chart. JS toggles .aa-fs-active
  // (CSS does the layout) and re-fits the tree to the new canvas size.
  function isFullscreen() {
    var s = $("aa-stage");
    return !!(s && s.classList.contains("aa-fs-active"));
  }
  function wireFullscreen() {
    var btn = $("aa-fs-btn"), stage = $("aa-stage");
    if (!btn || !stage) return;
    function fsEl() { return document.fullscreenElement || document.webkitFullscreenElement || null; }
    btn.addEventListener("click", function () {
      if (fsEl() === stage) {
        (document.exitFullscreen || document.webkitExitFullscreen || function () {}).call(document);
      } else {
        (stage.requestFullscreen || stage.webkitRequestFullscreen || function () {}).call(stage);
      }
    });
    function onChange() {
      var active = fsEl() === stage;
      stage.classList.toggle("aa-fs-active", active);
      var label = $("aa-fs-label");
      if (label) label.textContent = active ? "Exit" : "Fullscreen";
      btn.setAttribute("title", active ? "Exit fullscreen" : "Fullscreen");
      if (active && typeof closePanel === "function") closePanel();   // don't carry the side panel into fullscreen
      // Let the browser apply fullscreen layout before re-fitting the tree.
      setTimeout(function () { if (typeof window.aaRefit === "function") window.aaRefit(); }, 140);
    }
    document.addEventListener("fullscreenchange", onChange);
    document.addEventListener("webkitfullscreenchange", onChange);
  }

  // ---------- HD screenshot ----------
  // Export the whole rendered tree as a high-resolution PNG (targets ~12K wide,
  // capped to stay within browser canvas limits) so it stays crisp when zoomed.
  // The SVG is cloned, framed to the full content bounds (independent of the
  // on-screen zoom/pan), and the styles that come from external CSS (link
  // strokes + label font) are baked in so the standalone image matches the view.
  function takeScreenshot(done) {
    function fail() { if (done) done(false); }
    var svg = document.querySelector("#body svg");
    var visLive = svg && svg.querySelector("g");
    if (!svg || !visLive) return fail();

    var bbox;
    try { bbox = visLive.getBBox(); } catch (e) { return fail(); }
    if (!bbox.width || !bbox.height) return fail();

    var pad = 40;
    var vbX = bbox.x - pad, vbY = bbox.y - pad;
    var vbW = bbox.width + pad * 2, vbH = bbox.height + pad * 2;

    var clone = svg.cloneNode(true);
    clone.setAttribute("viewBox", vbX + " " + vbY + " " + vbW + " " + vbH);
    clone.setAttribute("preserveAspectRatio", "xMidYMid meet");
    var visClone = clone.querySelector("g");
    if (visClone) visClone.setAttribute("transform", "translate(0,0)");   // drop interactive zoom

    // Bake external-CSS styling into the standalone SVG so it renders identically.
    var linkEl = svg.querySelector("path.link");
    var textEl = svg.querySelector(".node text");
    var bodyCS = getComputedStyle(document.body);
    var linkStroke = linkEl ? getComputedStyle(linkEl).stroke : "#888";
    var linkWidth  = linkEl ? getComputedStyle(linkEl).strokeWidth : "1.5px";
    var fontFamily = textEl ? getComputedStyle(textEl).fontFamily
                            : "'SFMono-Regular', Consolas, monospace";
    var bg = (bodyCS.getPropertyValue("--cgt-bg") || "#ffffff").trim() || "#ffffff";

    var styleEl = document.createElementNS("http://www.w3.org/2000/svg", "style");
    styleEl.textContent =
      "path.link{fill:none;stroke:" + linkStroke + ";stroke-width:" + linkWidth + ";}" +
      ".node text{font-family:" + fontFamily + ";font-size:12px;}" +
      "text{font-family:" + fontFamily + ";}";
    clone.insertBefore(styleEl, clone.firstChild);

    // High-res output, capped by per-dimension and total-area limits so huge
    // trees don't exceed what the browser's canvas can allocate.
    var TARGET_W = 12000, MAX_DIM = 16000, MAX_AREA = 100e6;
    var scale = TARGET_W / vbW;
    var outW = vbW * scale, outH = vbH * scale;
    if (outW > MAX_DIM) { var s1 = MAX_DIM / outW; outW *= s1; outH *= s1; }
    if (outH > MAX_DIM) { var s2 = MAX_DIM / outH; outW *= s2; outH *= s2; }
    if (outW * outH > MAX_AREA) { var s3 = Math.sqrt(MAX_AREA / (outW * outH)); outW *= s3; outH *= s3; }
    outW = Math.max(1, Math.round(outW));
    outH = Math.max(1, Math.round(outH));
    clone.setAttribute("width", outW);
    clone.setAttribute("height", outH);

    var xml = new XMLSerializer().serializeToString(clone);
    if (xml.indexOf("xmlns=") === -1) {
      xml = xml.replace("<svg", '<svg xmlns="http://www.w3.org/2000/svg"');
    }
    var svgUrl = URL.createObjectURL(new Blob([xml], { type: "image/svg+xml;charset=utf-8" }));

    var img = new Image();
    img.onload = function () {
      try {
        var canvas = document.createElement("canvas");
        canvas.width = outW;
        canvas.height = outH;
        var ctx = canvas.getContext("2d");
        ctx.fillStyle = bg;
        ctx.fillRect(0, 0, outW, outH);
        ctx.drawImage(img, 0, 0, outW, outH);
        URL.revokeObjectURL(svgUrl);
        canvas.toBlob(function (blob) {
          if (!blob) return fail();
          var a = document.createElement("a");
          var dl = URL.createObjectURL(blob);
          a.href = dl;
          a.download = "address-graph-" + outW + "x" + outH + ".png";
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          setTimeout(function () { URL.revokeObjectURL(dl); }, 2000);
          if (done) done(true);
        }, "image/png");
      } catch (e) { URL.revokeObjectURL(svgUrl); fail(); }
    };
    img.onerror = function () { URL.revokeObjectURL(svgUrl); fail(); };
    img.src = svgUrl;
  }

  function wireScreenshot() {
    var btn = $("aa-shot-btn");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var label = $("aa-shot-label");
      var restore = label ? label.textContent : "";
      function flash(msg) {
        if (!label) return;
        label.textContent = msg;
        setTimeout(function () { label.textContent = restore; }, 1500);
      }
      if (!window.root) { flash("no chart"); return; }
      if (label) label.textContent = "saving…";
      // Defer one tick so the "saving…" label paints before the heavy rasterization.
      setTimeout(function () {
        takeScreenshot(function (ok) { flash(ok ? "saved ✓" : "failed"); });
      }, 30);
    });
  }

  function init() {
    var input = $("address-input"), btn = $("analyze-btn");
    wireTxLimit();
    wireWatchList();
    wireFullscreen();
    wireScreenshot();
    if (btn) btn.addEventListener("click", function () { analyze(input ? input.value : ""); });
    if (input) input.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); analyze(input.value); }
    });
    wireChainTabs();
    // Set the active chain from the pre-selected tab (Bitcoin) BEFORE any analyse,
    // and sync the search bar / stat cards to it.
    var activeTab = document.querySelector("#aa-chain-tabs .chain-tab.active") ||
                    document.querySelector('#aa-chain-tabs .chain-tab[data-chain="bitcoin"]');
    var slug = (activeTab && CHAINS[activeTab.getAttribute("data-chain")]) ? activeTab.getAttribute("data-chain") : "bitcoin";
    activeChain = CHAINS[slug];
    applyChainUi(slug, activeTab);
    watchTheme();
    // Deep link: ?address=... or ?txid=... (analyze() auto-detects the type).
    var q = /[?&]txid=([^&]+)/.exec(location.search) || /[?&]address=([^&]+)/.exec(location.search);
    if (q && input) { input.value = decodeURIComponent(q[1]); analyze(input.value); }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();

  // Expose the hooks arf.js delegates to.
  window.handleNodeClick = handleNodeClick;
  window.renderPanelContent = renderPanelContent;
  window.AddressAnalysis = { analyze: analyze };
})();
