/*
 * Public Key Toolkit — X/Y, HASH160 & every Bitcoin address type.
 * Self-contained: depends only on CryptoJS (loaded before this file).
 * Exposes window.PublicKeyToolkit.analyze() and window.exportOne().
 *
 * Input (auto-detected):
 *   • Public key   — compressed (02/03 + 64 hex) or uncompressed (04 + 128 hex)
 *   • HASH160      — 40 hex characters (RIPEMD-160 of a public key)
 *   • Address      — legacy P2PKH (1…), P2SH (3…) or native SegWit (bc1…)
 *
 * For an address, the public key is recovered by scanning its spending
 * transactions for the key it revealed on-chain (blockstream.info, with
 * blockchain.info as a fallback). All key math runs locally in the browser.
 */
(function () {
    "use strict";

    // ---- Constants -------------------------------------------------------
    const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    // secp256k1 field prime (p = 2^256 - 2^32 - 977; p % 4 == 3)
    const P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');

    // ---- Low-level converters -------------------------------------------
    function hexToBytes(hex) {
        if (!hex || typeof hex !== 'string') return new Uint8Array();
        hex = hex.replace(/^0x/i, '');
        if (hex.length % 2 !== 0) hex = '0' + hex;
        const m = hex.match(/.{1,2}/g);
        return m ? new Uint8Array(m.map(b => parseInt(b, 16))) : new Uint8Array();
    }
    function bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // ---- Hashing (CryptoJS) ---------------------------------------------
    function sha256hex(hex) { return CryptoJS.SHA256(CryptoJS.enc.Hex.parse(hex)).toString(); }
    function ripe160hex(hex) { return CryptoJS.RIPEMD160(CryptoJS.enc.Hex.parse(hex)).toString(); }
    function hash160hex(hex) { return ripe160hex(sha256hex(hex)); }

    // ---- secp256k1 point decompression ----------------------------------
    function modpow(base, exp, mod) {
        base %= mod; let r = 1n;
        while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; exp >>= 1n; base = (base * base) % mod; }
        return r;
    }
    // Decompress a compressed pubkey hex (02/03 + 64 hex) -> { x, y } BigInts.
    function decompress(compressedHex) {
        const prefix = compressedHex.slice(0, 2);
        const x = BigInt('0x' + compressedHex.slice(2));
        if (x <= 0n || x >= P) throw new Error("Public key X is out of range.");
        const ySq = (modpow(x, 3n, P) + 7n) % P;
        let y = modpow(ySq, (P + 1n) / 4n, P);
        // Confirm the point is actually on the curve.
        if ((y * y) % P !== ySq) throw new Error("Invalid public key (point is not on the secp256k1 curve).");
        const wantOdd = prefix === '03';
        if ((y & 1n) !== (wantOdd ? 1n : 0n)) y = P - y;
        return { x, y };
    }
    const to64 = (n) => n.toString(16).padStart(64, '0');
    function compressPoint(x, y) { return ((y & 1n) ? '03' : '02') + to64(x); }
    function uncompressPoint(x, y) { return '04' + to64(x) + to64(y); }

    // Parse any pubkey hex -> { x, y, compressed, uncompressed }.
    function parsePubkey(hex) {
        hex = hex.toLowerCase();
        if (/^0[23][0-9a-f]{64}$/.test(hex)) {
            const { x, y } = decompress(hex);
            return { x, y, compressed: hex, uncompressed: uncompressPoint(x, y) };
        }
        if (/^04[0-9a-f]{128}$/.test(hex)) {
            const x = BigInt('0x' + hex.slice(2, 66));
            const y = BigInt('0x' + hex.slice(66));
            if (x >= P || y >= P) throw new Error("Public key coordinate out of range.");
            if ((y * y) % P !== (modpow(x, 3n, P) + 7n) % P)
                throw new Error("Invalid public key (point is not on the secp256k1 curve).");
            return { x, y, compressed: compressPoint(x, y), uncompressed: hex };
        }
        throw new Error("Not a valid public key.");
    }

    // ---- Base58 / Base58Check -------------------------------------------
    function b58encode(bytes) {
        let num = 0n;
        for (const b of bytes) num = num * 256n + BigInt(b);
        let str = "";
        while (num > 0n) { str = B58[Number(num % 58n)] + str; num /= 58n; }
        for (const b of bytes) { if (b === 0) str = "1" + str; else break; }
        return str || "1";
    }
    function b58decode(str) {
        let num = 0n;
        for (const ch of str) {
            const v = B58.indexOf(ch);
            if (v < 0) throw new Error("Invalid Base58 character.");
            num = num * 58n + BigInt(v);
        }
        let hex = num.toString(16);
        if (hex.length % 2) hex = '0' + hex;
        let bytes = Array.from(hexToBytes(hex));
        for (const ch of str) { if (ch === '1') bytes.unshift(0); else break; }
        return new Uint8Array(bytes);
    }
    // base58check from version byte(s) hex + payload hex.
    function base58check(versionHex, payloadHex) {
        const dataHex = versionHex + payloadHex;
        const chk = sha256hex(sha256hex(dataHex)).substring(0, 8);
        return b58encode(hexToBytes(dataHex + chk));
    }
    // Decode a base58check address -> { versionHex, payloadHex }. Throws on bad checksum.
    function base58checkDecode(addr) {
        const raw = b58decode(addr);
        if (raw.length < 5) throw new Error("Address too short.");
        const body = raw.slice(0, raw.length - 4);
        const chk = bytesToHex(raw.slice(raw.length - 4));
        const calc = sha256hex(sha256hex(bytesToHex(body))).substring(0, 8);
        if (chk !== calc) throw new Error("Bad address checksum.");
        return { versionHex: bytesToHex(body.slice(0, 1)), payloadHex: bytesToHex(body.slice(1)) };
    }

    // ---- Bech32 / Bech32m (BIP173 / BIP350) -----------------------------
    function bech32Polymod(values) {
        const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let chk = 1;
        for (const v of values) {
            const b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
        }
        return chk;
    }
    function hrpExpand(hrp) {
        const out = [];
        for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
        out.push(0);
        for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
        return out;
    }
    function convertBits(data, from, to, pad) {
        let acc = 0, bits = 0; const out = []; const maxv = (1 << to) - 1;
        for (const value of data) {
            if (value < 0 || value >> from) throw new Error("Invalid data for bech32 conversion.");
            acc = (acc << from) | value; bits += from;
            while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
        }
        if (pad) { if (bits > 0) out.push((acc << (to - bits)) & maxv); }
        else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error("Invalid padding in bech32.");
        return out;
    }
    function bech32Create(hrp, data, spec) {
        const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
        const constant = spec === 'bech32m' ? 0x2bc830a3 : 1;
        const mod = bech32Polymod(values) ^ constant;
        const out = [];
        for (let i = 0; i < 6; i++) out.push((mod >> (5 * (5 - i))) & 31);
        return out;
    }
    // Encode a segwit address. witver 0 -> bech32, 1+ -> bech32m.
    function segwitEncode(hrp, witver, programBytes) {
        const spec = witver === 0 ? 'bech32' : 'bech32m';
        const data = [witver].concat(convertBits(Array.from(programBytes), 8, 5, true));
        const combined = data.concat(bech32Create(hrp, data, spec));
        return hrp + '1' + combined.map(d => BECH32_CHARSET[d]).join('');
    }
    // Decode a segwit address -> { hrp, version, programHex }. Throws if invalid.
    function segwitDecode(addr) {
        const lower = addr.toLowerCase();
        if (addr !== lower && addr !== addr.toUpperCase()) throw new Error("Mixed-case bech32 address.");
        const pos = lower.lastIndexOf('1');
        if (pos < 1 || pos + 7 > lower.length) throw new Error("Invalid bech32 layout.");
        const hrp = lower.slice(0, pos);
        const dataChars = lower.slice(pos + 1);
        const data = [];
        for (const ch of dataChars) {
            const v = BECH32_CHARSET.indexOf(ch);
            if (v < 0) throw new Error("Invalid bech32 character.");
            data.push(v);
        }
        const witver = data[0];
        const spec = witver === 0 ? 'bech32' : 'bech32m';
        const check = bech32Polymod(hrpExpand(hrp).concat(data)) ^ (spec === 'bech32m' ? 0x2bc830a3 : 1);
        if (check !== 0) throw new Error("Bad bech32 checksum.");
        const program = convertBits(data.slice(1, data.length - 6), 5, 8, false);
        return { hrp, version: witver, programHex: bytesToHex(program) };
    }

    // ---- Address derivation from a HASH160 ------------------------------
    // Returns { p2pkh, p2sh, bech32 } for a 20-byte pubkey-hash (hex).
    function addressesFromHash160(h160) {
        const redeem = "0014" + h160;                       // P2WPKH witness program
        return {
            p2pkh: base58check("00", h160),
            p2sh: base58check("05", hash160hex(redeem)),
            bech32: segwitEncode("bc", 0, hexToBytes(h160))
        };
    }

    // ---- Transaction parsing (for public-key recovery from an address) ---
    function readVarInt(buf, offset) {
        const prefix = buf[offset];
        if (prefix < 0xFD) return { val: prefix, size: 1 };
        if (prefix === 0xFD) return { val: buf[offset + 1] | (buf[offset + 2] << 8), size: 3 };
        if (prefix === 0xFE) return { val: buf[offset + 1] | (buf[offset + 2] << 8) | (buf[offset + 3] << 16) | (buf[offset + 4] << 24), size: 5 };
        return { val: buf[offset + 1], size: 9 };
    }
    function parseHexTransaction(txRaw) {
        const buf = hexToBytes(txRaw);
        let cursor = 4;                                      // skip version
        let isSegwit = false;
        if (buf[cursor] === 0x00 && buf[cursor + 1] === 0x01) { isSegwit = true; cursor += 2; }
        const inCount = readVarInt(buf, cursor); cursor += inCount.size;
        const inputs = [];
        for (let i = 0; i < inCount.val; i++) {
            cursor += 36;                                    // prevout hash + index
            const sLen = readVarInt(buf, cursor); cursor += sLen.size;
            const script_hex = bytesToHex(buf.slice(cursor, cursor + sLen.val)); cursor += sLen.val;
            cursor += 4;                                     // sequence
            inputs.push({ script_hex });
        }
        const outCount = readVarInt(buf, cursor); cursor += outCount.size;
        for (let i = 0; i < outCount.val; i++) {
            cursor += 8;                                     // value
            const sLen = readVarInt(buf, cursor); cursor += sLen.size + sLen.val;
        }
        if (isSegwit) {
            for (let i = 0; i < inCount.val; i++) {
                const wCount = readVarInt(buf, cursor); cursor += wCount.size;
                const witnesses = [];
                for (let j = 0; j < wCount.val; j++) {
                    const iLen = readVarInt(buf, cursor); cursor += iLen.size;
                    witnesses.push(bytesToHex(buf.slice(cursor, cursor + iLen.val)));
                    cursor += iLen.val;
                }
                inputs[i].witness = witnesses;
            }
        }
        return { inputs };
    }
    // Pull the first plausible compressed/uncompressed pubkey out of a scriptSig.
    function pubkeyFromScriptSig(scr) {
        const buf = hexToBytes(scr);
        for (let i = 0; i < buf.length; i++) {
            const len = buf[i];
            if ((len === 33 || len === 65) && i + 1 + len <= buf.length) {
                const cand = bytesToHex(buf.slice(i + 1, i + 1 + len));
                if (/^0[23][0-9a-f]{64}$/.test(cand) || /^04[0-9a-f]{128}$/.test(cand)) return cand;
            }
        }
        return "";
    }
    // Every public key exposed by the inputs of one transaction.
    function pubkeysFromTx(parsed) {
        const pubs = [];
        for (const inp of parsed.inputs) {
            if (inp.script_hex) { const p = pubkeyFromScriptSig(inp.script_hex); if (p) pubs.push(p); }
            if (inp.witness && inp.witness.length) {
                const w = inp.witness[inp.witness.length - 1];
                if (/^0[23][0-9a-f]{64}$/.test(w) || /^04[0-9a-f]{128}$/.test(w)) pubs.push(w);
            }
        }
        return pubs;
    }

    // ---- Network ---------------------------------------------------------
    async function getRawTx(txid) {
        const urls = [
            `https://blockstream.info/api/tx/${txid}/hex`,
            `https://blockchain.info/rawtx/${txid}?format=hex`
        ];
        for (const url of urls) {
            try {
                const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
                if (resp.ok) {
                    const raw = (await resp.text()).trim();
                    if (raw.length > 50 && !raw.includes("not found") && !raw.startsWith("<!DOCTYPE")) return raw;
                }
            } catch (e) { /* try next */ }
            await new Promise(r => setTimeout(r, 250));
        }
        throw new Error(`Could not fetch transaction ${txid.substring(0, 8)}…`);
    }
    // List an address's txids, newest first, up to `want`. Returns [] if none, null if every explorer failed.
    async function fetchAddressTxids(addr, want, onProgress) {
        let anyOk = false;
        try {
            let txids = [], lastSeen = '', guard = 0;
            while (txids.length < want && guard < 5000) {
                guard++;
                const url = lastSeen
                    ? `https://blockstream.info/api/address/${addr}/txs/chain/${lastSeen}`
                    : `https://blockstream.info/api/address/${addr}/txs/chain`;
                const resp = await fetch(url, { signal: AbortSignal.timeout(15000) });
                if (!resp.ok) break;
                anyOk = true;
                const arr = await resp.json();
                if (!Array.isArray(arr) || arr.length === 0) break;
                for (const t of arr) txids.push(t.txid);
                lastSeen = arr[arr.length - 1].txid;
                if (onProgress) onProgress({ listed: txids.length, target: want });
                if (arr.length < 25) break;
                await new Promise(r => setTimeout(r, 120));
            }
            if (txids.length > 0) return txids.slice(0, want);
            if (anyOk) return [];
        } catch (e) { /* fall through */ }
        try {
            let txids = [], total = null, offset = 0; const PAGE = 50;
            while (txids.length < want) {
                const pageLimit = Math.min(PAGE, want - txids.length);
                const url = `https://blockchain.info/rawaddr/${addr}?limit=${pageLimit}&offset=${offset}&cors=true`;
                const resp = await fetch(url, { signal: AbortSignal.timeout(15000) });
                if (!resp.ok) break;
                anyOk = true;
                const data = await resp.json();
                if (!data || !Array.isArray(data.txs) || data.txs.length === 0) break;
                if (total === null) total = data.n_tx || 0;
                for (const tx of data.txs) txids.push(tx.hash);
                offset += data.txs.length;
                if (onProgress) onProgress({ listed: txids.length, target: Math.min(want, total || want) });
                if (total && offset >= total) break;
                if (data.txs.length < pageLimit) break;
                await new Promise(r => setTimeout(r, 150));
            }
            if (txids.length > 0) return txids.slice(0, want);
            if (anyOk) return [];
        } catch (e) { /* both failed */ }
        return anyOk ? [] : null;
    }

    // Recover the public key behind an address by scanning its spending txs.
    // The matching pubkey is the one whose hash160 maps to this exact address.
    async function recoverPubkeyForAddress(addr, targetH160, want, onProgress) {
        const txids = await fetchAddressTxids(addr, want, onProgress);
        if (txids === null) throw new Error("Couldn't reach a block explorer (it may be rate-limiting). Try again shortly.");
        if (txids.length === 0) return null;
        const BATCH = 4;
        let scanned = 0;
        for (let b = 0; b < txids.length; b += BATCH) {
            const slice = txids.slice(b, b + BATCH);
            const found = await Promise.all(slice.map(async (h) => {
                try {
                    const parsed = parseHexTransaction(await getRawTx(h));
                    for (const pub of pubkeysFromTx(parsed)) {
                        if (hash160hex(pub) === targetH160) return pub;
                    }
                } catch (e) { /* skip */ }
                return null;
            }));
            const hit = found.find(Boolean);
            if (hit) return hit;
            scanned += slice.length;
            if (onProgress) onProgress({ scanned, target: txids.length });
            await new Promise(r => setTimeout(r, 120));
        }
        return null;                                          // address never spent -> pubkey not revealed
    }

    // ---- Balance / Received / TX (same box as the R·S·Z tool) ------------
    function formatBtc(sats) {
        const n = Number(sats || 0) / 1e8;
        const s = n.toFixed(8).replace(/\.?0+$/, '');
        return (s || '0') + ' BTC';
    }
    async function fetchAddressStats(addr) {
        try {
            const resp = await fetch(`https://blockstream.info/api/address/${addr}`, { signal: AbortSignal.timeout(15000) });
            if (resp.ok) {
                const d = await resp.json();
                const c = d.chain_stats || {}, m = d.mempool_stats || {};
                const funded = (c.funded_txo_sum || 0) + (m.funded_txo_sum || 0);
                const spent = (c.spent_txo_sum || 0) + (m.spent_txo_sum || 0);
                return { balance: funded - spent, received: funded, tx: (c.tx_count || 0) + (m.tx_count || 0) };
            }
        } catch (e) { /* fall through */ }
        try {
            const resp = await fetch(`https://blockchain.info/rawaddr/${addr}?limit=0&cors=true`, { signal: AbortSignal.timeout(15000) });
            if (resp.ok) {
                const d = await resp.json();
                return { balance: d.final_balance || 0, received: d.total_received || 0, tx: d.n_tx || 0 };
            }
        } catch (e) { /* give up */ }
        return null;
    }
    function setStats(stats) {
        const b = document.getElementById('pkt-stat-balance');
        const r = document.getElementById('pkt-stat-received');
        const t = document.getElementById('pkt-stat-tx');
        if (b) b.textContent = stats ? formatBtc(stats.balance) : '0 BTC';
        if (r) r.textContent = stats ? formatBtc(stats.received) : '0 BTC';
        if (t) t.textContent = stats ? String(stats.tx) : '0';
    }

    // Fill the live balance slot under each derived address (Balance · Received · Tx).
    // Funds may sit on any address format, so every one is looked up independently.
    async function fillAddressBalances(root) {
        if (!root) return;
        const nodes = root.querySelectorAll('.pkt-addr-stats[data-bal]');
        await Promise.all(Array.prototype.map.call(nodes, async function (el) {
            const address = el.getAttribute('data-bal');
            try {
                const s = await fetchAddressStats(address);
                if (s) {
                    el.innerHTML = 'Balance <b>' + escapeHtml(formatBtc(s.balance)) +
                        '</b> &middot; Received <b>' + escapeHtml(formatBtc(s.received)) +
                        '</b> &middot; <b>' + Number(s.tx || 0) + '</b> tx';
                    if (s.received > 0) el.classList.add('pkt-has-funds');
                } else {
                    el.textContent = 'Balance unavailable'; el.classList.add('pkt-bal-na');
                }
            } catch (e) {
                el.textContent = 'Balance unavailable'; el.classList.add('pkt-bal-na');
            }
        }));
    }

    // ---- HTML helpers (mirror the R·S·Z tool look) -----------------------
    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function copyBtn(text) {
        if (text == null || text === '') return '';
        return '<button type="button" class="rsz-copy" title="Copy" data-copy="' +
            escapeHtml(text) + '"><img src="../assets/svgs/regular/copy.svg" width="12" height="12" alt="copy"></button>';
    }
    function line(label, val, addr) {
        return '<div class="rsz-line"><span class="rsz-tag pkt-tag">' + escapeHtml(label) + '</span>' +
            '<code class="rsz-val ' + (addr ? 'rsz-addr-val' : '') + '">' + escapeHtml(val || '—') + '</code>' +
            copyBtn(val) + '</div>';
    }
    // Address line plus a slot that fillAddressBalances() populates with its live stats.
    function addrRow(label, address) {
        return line(label, address, true) +
            '<div class="pkt-addr-stats" data-bal="' + escapeHtml(address) + '">Checking balance…</div>';
    }
    function fallbackCopy(text, done) {
        try {
            const ta = document.createElement('textarea');
            ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select(); document.execCommand('copy');
            document.body.removeChild(ta); done();
        } catch (e) { /* ignore */ }
    }
    document.addEventListener('click', function (ev) {
        const btn = ev.target && ev.target.closest ? ev.target.closest('.rsz-copy[data-copy]') : null;
        if (!btn) return;
        const val = btn.getAttribute('data-copy');
        const done = () => { btn.classList.add('copied'); setTimeout(() => btn.classList.remove('copied'), 1200); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(val).then(done).catch(() => fallbackCopy(val, done));
        } else fallbackCopy(val, done);
    });

    function getOutputHeader() {
        return '<div class="result-header">CRYPTOGRAPHYTUBE<span class="tool-tag">Public Key Toolkit</span></div>' +
            '<div class="download-tools"><button class="btn-small btn-txt" title="Export as TXT" onclick="exportOne(\'pkt_out\',\'txt\')">' +
            '<img src="../assets/svgs/solid/download.svg" width="12" height="12" alt=""> SAVE TXT</button></div>';
    }

    // ---- Rendering -------------------------------------------------------
    // Full breakdown for a known public key (direct input or recovered).
    function renderPubkey(pk, note) {
        const h160c = hash160hex(pk.compressed);
        const h160u = hash160hex(pk.uncompressed);
        const a = addressesFromHash160(h160c);              // segwit uses the compressed hash
        let html = '';
        if (note) html += '<div class="rsz-summary"><span class="rsz-chip rsz-chip-ok">' + escapeHtml(note) + '</span></div>';

        html += '<div class="rsz-thead rsz-full"><div><img src="../assets/svgs/solid/key.svg" width="13" height="13" alt=""> Coordinates &amp; Public Key</div></div>';
        html += '<div class="rsz-row rsz-full"><div class="rsz-col">';
        html += line('X (dec)', pk.x.toString(10));
        html += line('Y (dec)', pk.y.toString(10));
        html += line('X (hex)', to64(pk.x));
        html += line('Y (hex)', to64(pk.y));
        html += line('Compressed', pk.compressed);
        html += line('Uncompressed', pk.uncompressed);
        html += '</div></div>';

        html += '<div class="rsz-thead rsz-full"><div><img src="../assets/svgs/solid/hashtag.svg" width="13" height="13" alt=""> HASH160 &amp; Addresses</div></div>';
        html += '<div class="rsz-row rsz-full"><div class="rsz-col">';
        html += line('HASH160', h160c);
        html += addrRow('P2PKH (1…)', a.p2pkh);
        html += addrRow('P2SH-P2WPKH (3…)', a.p2sh);
        html += addrRow('Native SegWit (bc1…)', a.bech32);
        html += addrRow('P2PKH uncompressed', base58check('00', h160u));
        html += '</div></div>';
        return html;
    }

    function renderHash160(h160) {
        const a = addressesFromHash160(h160);
        let html = '<div class="rsz-summary"><span class="rsz-chip">HASH160 input</span></div>';
        html += '<div class="rsz-thead rsz-full"><div><img src="../assets/svgs/solid/hashtag.svg" width="13" height="13" alt=""> HASH160 &amp; Addresses</div></div>';
        html += '<div class="rsz-row rsz-full"><div class="rsz-col">';
        html += line('HASH160', h160);
        html += addrRow('P2PKH (1…)', a.p2pkh);
        html += addrRow('P2SH-P2WPKH (3…)', a.p2sh);
        html += addrRow('Native SegWit (bc1…)', a.bech32);
        html += '</div></div>';
        html += '<div class="rsz-status">The public key can only be revealed by a spending transaction — enter the address and enable recovery to fetch it.</div>';
        return html;
    }

    // ---- Address decoding ------------------------------------------------
    // -> { type, h160, program, addr }. h160 set for P2PKH / P2SH / P2WPKH.
    function decodeAddress(addr) {
        if (/^(bc1|tb1)/i.test(addr)) {
            const d = segwitDecode(addr);
            const type = d.programHex.length === 40 ? 'P2WPKH (native SegWit)'
                : d.programHex.length === 64 ? 'P2WSH / P2TR (native SegWit)'
                : 'SegWit v' + d.version;
            return { type, h160: d.programHex.length === 40 ? d.programHex : '', program: d.programHex, addr };
        }
        const d = base58checkDecode(addr);
        if (d.versionHex === '00') return { type: 'P2PKH (legacy)', h160: d.payloadHex, program: '', addr };
        if (d.versionHex === '05') return { type: 'P2SH', h160: '', program: d.payloadHex, addr };
        return { type: 'Base58 (version 0x' + d.versionHex + ')', h160: d.payloadHex, program: '', addr };
    }

    // ---- Main entry ------------------------------------------------------
    async function analyze() {
        const inputEl = document.getElementById('pkt_input');
        const out = document.getElementById('pkt_out');
        if (!inputEl || !out) return;
        const raw = inputEl.value.trim();
        if (!raw) return;

        const header = getOutputHeader();
        const status = (msg) => { out.innerHTML = header + '<div class="rsz-status">' + escapeHtml(msg) + '</div>'; };
        const scan = document.getElementById('pkt-scan');
        const limitEl = document.getElementById('pkt-tx-limit');
        let want = limitEl ? parseInt(limitEl.value, 10) : 50;
        if (!want || want < 1) want = 50;

        try {
            const hex = raw.replace(/^0x/i, '').toLowerCase();

            // 1) Public key (compressed or uncompressed)
            if (/^0[23][0-9a-f]{64}$/.test(hex) || /^04[0-9a-f]{128}$/.test(hex)) {
                setStats(null);
                out.innerHTML = header + renderPubkey(parsePubkey(hex),
                    hex.length === 66 ? 'Compressed public key' : 'Uncompressed public key');
                fillAddressBalances(out);
                return;
            }

            // 2) HASH160
            if (/^[0-9a-f]{40}$/.test(hex)) {
                setStats(null);
                out.innerHTML = header + renderHash160(hex);
                fillAddressBalances(out);
                return;
            }

            // 3) Address
            status('Decoding address…');
            let dec;
            try { dec = decodeAddress(raw); }
            catch (e) { throw new Error('Unrecognised input. Paste a public key (02/03/04…), a 40-hex HASH160, or a Bitcoin address. (' + e.message + ')'); }

            // Balance / Received / TX for the address (same box as the R·S·Z tool).
            status('Fetching balance…');
            try { setStats(await fetchAddressStats(raw)); } catch (e) { setStats(null); }

            let html = '<div class="rsz-summary"><span class="rsz-chip">' + escapeHtml(dec.type) + '</span></div>';
            html += '<div class="rsz-thead rsz-full"><div><img src="../assets/svgs/solid/wallet.svg" width="13" height="13" alt=""> Address</div></div>';
            html += '<div class="rsz-row rsz-full"><div class="rsz-col">';
            html += line('Address', dec.addr, true);
            if (dec.h160) html += line('HASH160', dec.h160);
            if (dec.program && !dec.h160) html += line('Witness / script', dec.program);
            html += '</div></div>';

            const canRecover = dec.h160 && dec.h160.length === 40;
            if (scan && scan.checked && canRecover) {
                out.innerHTML = header + html +
                    '<div class="rsz-status">Scanning transactions to recover the public key…</div>';
                const onProgress = (p) => {
                    out.innerHTML = header + html + '<div class="rsz-status">' +
                        (p.scanned != null
                            ? 'Scanning transactions… ' + p.scanned + ' / ' + p.target
                            : 'Listing transactions… ' + p.listed + (p.target ? ' / ' + p.target : '')) +
                        '</div>';
                };
                let pub = null;
                try { pub = await recoverPubkeyForAddress(raw, dec.h160, want, onProgress); }
                catch (e) { out.innerHTML = header + html + '<div class="rsz-error">' + escapeHtml(e.message) + '</div>'; return; }
                if (pub) {
                    html += renderPubkey(parsePubkey(pub), 'Public key recovered from an on-chain signature');
                } else {
                    html += '<div class="rsz-status rsz-empty">No public key found — this address has not spent funds yet, so it never revealed its key on-chain.</div>';
                }
            } else if (canRecover) {
                html += '<div class="rsz-status">Enable “Recover public key from an address” to scan transactions for the key revealed on-chain.</div>';
            } else {
                html += '<div class="rsz-status">Public-key recovery is available for P2PKH / P2WPKH addresses (which commit to a single key).</div>';
            }
            out.innerHTML = header + html;
            fillAddressBalances(out);
        } catch (e) {
            out.innerHTML = header + '<div class="rsz-error"><img src="../assets/svgs/solid/triangle-exclamation.svg" width="14" height="14" alt=""> Error: ' +
                escapeHtml(e.message) + '</div>';
        }
    }

    // ---- Export ----------------------------------------------------------
    function exportOne(id, type) {
        const el = document.getElementById(id);
        if (!el || el.innerText.trim().length < 5 || el.innerText.includes('Instructions:')) {
            alert('No results to export yet.'); return;
        }
        let text = 'CRYPTOGRAPHYTUBE REPORT\nTOOL: PUBLIC KEY TOOLKIT\nGENERATED: ' +
            new Date().toLocaleString() + '\n' + '-'.repeat(50) + '\n\n' + (el.innerText || el.textContent);
        if (type === 'txt') {
            const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
            const a = document.createElement('a');
            a.href = url; a.download = 'CryptographyTube_PublicKeyToolkit.txt';
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
        }
    }

    // ---- Expose ----------------------------------------------------------
    window.PublicKeyToolkit = { analyze: analyze, setStats: setStats };
    window.exportOne = exportOne;
})();
