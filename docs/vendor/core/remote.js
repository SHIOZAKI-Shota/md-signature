import { toBase64 } from "./encoding.js";
import { tsaFromJson, toJsonResult } from "./json.js";
const endpoint = (base, path) => base.replace(/\/+$/, "") + path;
async function post(url, body, o) {
    const res = await (o.fetch ?? globalThis.fetch)(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: o.signal });
    const text = await res.text();
    let json;
    try {
        json = JSON.parse(text);
    }
    catch {
        throw new Error(`verification server answered HTTP ${res.status} without JSON`);
    }
    if (!res.ok)
        throw new Error(`verification server: ${json?.error ?? `HTTP ${res.status}`}`);
    return json;
}
export function remoteVerify(baseUrl, document, o = {}) {
    return post(endpoint(baseUrl, "/v1/verify"), { document }, o);
}
// for VerifyOptions.tsaVerifier: the server's trust store decides, this side reports its verdict
export function remoteTsaVerifier(baseUrl, o = {}) {
    return async (tsaToken, sigBytes) => {
        try {
            return tsaFromJson(await post(endpoint(baseUrl, "/v1/tsa"), { tsa_token: tsaToken, sig: toBase64(sigBytes) }, o));
        }
        catch (e) {
            return { status: "error", verified: false, detail: e.message };
        }
    };
}
export function compareResults(local, remote) {
    // only the JSON shape has a null error or snake_case block fields
    const isJson = (r) => r.error === null || r.signatures.some((s) => "hash_ok" in s);
    const l = isJson(local) ? local : toJsonResult(local);
    const side = (r, i) => {
        const s = r.signatures.find((x) => x.index === i);
        return s ? { status: s.status, code: s.code, tsaVerified: s.tsa ? s.tsa.verified === true : null, tsaSigner: s.tsa?.signer ?? null } : null;
    };
    const indexes = [...new Set([...l.signatures, ...remote.signatures].map((s) => s.index))].sort((a, b) => a - b);
    const blocks = indexes.map((index) => {
        const a = side(l, index);
        const b = side(remote, index);
        return { index, local: a, remote: b, agree: !!a && !!b && a.status === b.status && a.code === b.code, tsaAgree: !!a && !!b && a.tsaVerified === b.tsaVerified };
    });
    const agreementAgree = l.agreement.status === remote.agreement.status;
    return { agree: blocks.every((b) => b.agree) && (l.error ?? null) === (remote.error ?? null) && agreementAgree, agreementAgree, tsaAgree: blocks.every((b) => b.tsaAgree), blocks };
}
