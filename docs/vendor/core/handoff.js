import { PAYLOAD_DOMAIN, signedPayload } from "./canonical.js";
import { bytesEqual, toBase64 } from "./encoding.js";
import { prepareSignature } from "./sign.js";
import { fromBase64Url, toBase64Url } from "./webauthn.js";
// --- CLI_SPEC 8: passkey signatures through a signing page
export const HANDOFF_VERSION = "1";
export const HANDOFF_METHODS = new Set(["tofu", "dns", "directory"]);
export class HandoffError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}
const parseUrl = (u) => {
    try {
        return new URL(u);
    }
    catch {
        return null;
    }
};
export function isSigningPageUrl(url) {
    const u = parseUrl(url);
    return !!u && u.protocol === "https:" && !!u.hostname && !u.username && !u.password;
}
// CLI_SPEC 8.4: a non-http(s) scheme or a loopback address, so a web site cannot collect signatures through the page
export function isHandoffReturnUrl(url) {
    const u = parseUrl(url);
    if (!u)
        return false;
    if (u.protocol !== "http:" && u.protocol !== "https:")
        return /^[a-z][a-z0-9+.-]*:$/.test(u.protocol);
    return u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "[::1]") && u.port !== "" && !u.username && !u.password;
}
// CLI_SPEC 8.5: the RP ID is the page's host or a parent domain of it
export function rpIdFitsPage(page, rpId) {
    const u = parseUrl(page);
    if (!u || !rpId)
        return false;
    const host = u.hostname.toLowerCase();
    const rp = rpId.toLowerCase();
    return host === rp || host.endsWith("." + rp);
}
function randomState() {
    return toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}
export function createHandoffRequest(page, o) {
    if (!isSigningPageUrl(page))
        throw new HandoffError("invalid-request", "the signing page must be an https:// URL");
    if (!isHandoffReturnUrl(o.returnUrl))
        throw new HandoffError("invalid-request", "the return URL must use its own scheme or a loopback address");
    if (o.op === "sign" && !o.payload)
        throw new HandoffError("invalid-request", "op=sign needs a payload");
    const state = o.state ?? randomState();
    const u = new URL(page);
    u.searchParams.set("v", HANDOFF_VERSION);
    u.searchParams.set("op", o.op);
    u.searchParams.set("return", o.returnUrl);
    u.searchParams.set("state", state);
    if (o.op === "sign")
        u.searchParams.set("payload", toBase64Url(o.payload));
    if (o.credential)
        u.searchParams.set("credential", o.credential);
    if (o.name)
        u.searchParams.set("name", o.name);
    // CLI_SPEC 8.2: the page asks the authenticator for user verification and refuses an assertion without UV
    if (o.op === "sign" && o.userVerification === "required")
        u.searchParams.set("user_verification", "required");
    return { url: u.toString(), state };
}
const b64u = (v) => {
    if (!v || !/^[A-Za-z0-9_-]+$/.test(v))
        return null;
    try {
        return fromBase64Url(v);
    }
    catch {
        return null;
    }
};
// null when the URL is not a version 1 answer; the caller matches state against its pending requests (CLI_SPEC 8.5)
export function parseHandoffResponse(url, op) {
    const u = parseUrl(url);
    if (!u)
        return null;
    const q = u.searchParams;
    const state = q.get("state");
    if (q.get("v") !== HANDOFF_VERSION || !state)
        return null;
    const error = q.get("error");
    if (error !== null)
        return { state, error: error === "cancelled" || error === "unsupported" ? error : "invalid-request" };
    if (op === "key") {
        const rpId = q.get("rp_id") ?? "";
        const key = b64u(q.get("key"));
        const credential = q.get("credential") ?? "";
        if (!rpId || !key || !b64u(credential))
            return null;
        return { state, op, rpId, key, credential };
    }
    const authenticatorData = b64u(q.get("authenticator_data"));
    const clientDataJSON = b64u(q.get("client_data"));
    const signature = b64u(q.get("sig"));
    if (!authenticatorData || !clientDataJSON || !signature)
        return null;
    return { state, op, assertion: { authenticatorData, clientDataJSON, signature } };
}
async function exchange(page, transport, op, o) {
    const req = createHandoffRequest(page, { op, ...o });
    const res = parseHandoffResponse(await transport(req), op);
    // security: an answer is accepted only for the state of this request (CLI_SPEC 8.5)
    if (!res || res.state !== req.state)
        throw new HandoffError("bad-response", "the signing page did not answer this request");
    if ("error" in res)
        throw new HandoffError(res.error, `the signing page answered ${res.error}`);
    return res;
}
export async function connectPasskeyViaPage(page, o) {
    const res = await exchange(page, o.transport, "key", { returnUrl: o.returnUrl });
    if (!("rpId" in res))
        throw new HandoffError("bad-response", "the signing page answered with the wrong operation");
    if (!rpIdFitsPage(page, res.rpId))
        throw new HandoffError("bad-response", `the passkey's RP ID ${res.rpId} does not belong to ${new URL(page).hostname}`);
    return { page, rpId: res.rpId, key: res.key, credential: res.credential };
}
export async function signViaPage(text, o) {
    if (!HANDOFF_METHODS.has(o.method))
        throw new HandoffError("invalid-request", `passkeys sign with method tofu, dns, or directory, not ${o.method}`);
    const { passkey, returnUrl, transport, name, ...rest } = o;
    const p = await prepareSignature(text, { ...rest, signer: { alg: "webauthn-es256", publicKey: passkey.key, rpId: passkey.rpId } });
    const res = await exchange(passkey.page, transport, "sign", { returnUrl, payload: p.payload, credential: passkey.credential, name, userVerification: p.userVerification });
    if (!("assertion" in res))
        throw new HandoffError("bad-response", "the signing page answered with the wrong operation");
    return p.finish(res.assertion);
}
// --- signing page side (CLI_SPEC 8.3)
export function parseSignedPayload(payload) {
    let text;
    try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(payload);
    }
    catch {
        return null;
    }
    const lines = text.split("\n");
    if (lines.shift() !== PAYLOAD_DOMAIN)
        return null;
    const fields = {};
    let last = "";
    for (const line of lines) {
        if (line.startsWith("  ") && last) {
            fields[last] += "\n" + line.slice(2);
            continue;
        }
        const i = line.indexOf("=");
        if (i <= 0)
            return null;
        last = line.slice(0, i);
        if (Object.hasOwn(fields, last))
            return null;
        fields[last] = line.slice(i + 1);
    }
    // only the canonical encoding is accepted, so what is shown is exactly what is signed
    return bytesEqual(signedPayload(fields), payload) ? fields : null;
}
export function checkHandoffRequest(url, rpId) {
    const u = parseUrl(url);
    if (!u)
        return { ok: false, error: "invalid-request", message: "not a URL" };
    const q = u.searchParams;
    const returnUrl = q.get("return") ?? "";
    const state = q.get("state") ?? "";
    // security: a request with another return URL is refused without redirecting (CLI_SPEC 8.4)
    if (!isHandoffReturnUrl(returnUrl))
        return { ok: false, error: "invalid-request", message: "the return URL must use its own scheme or a loopback address" };
    const back = { returnUrl, state };
    if (!/^[A-Za-z0-9_-]{22,}$/.test(state))
        return { ok: false, error: "invalid-request", message: "state must be at least 128 bits of base64url", ...back };
    if (q.get("v") !== HANDOFF_VERSION)
        return { ok: false, error: "unsupported", message: `unsupported version ${q.get("v")}`, ...back };
    const op = q.get("op");
    if (op === "key")
        return { ok: true, op, returnUrl, state };
    if (op !== "sign")
        return { ok: false, error: "invalid-request", message: `unknown op ${op}`, ...back };
    const payload = b64u(q.get("payload"));
    const fields = payload && parseSignedPayload(payload);
    if (!payload || !fields)
        return { ok: false, error: "invalid-request", message: "the payload is not an md-signature payload", ...back };
    if (fields.alg !== "webauthn-es256")
        return { ok: false, error: "unsupported", message: `alg ${fields.alg} is not webauthn-es256`, ...back };
    if (!HANDOFF_METHODS.has(fields.method ?? ""))
        return { ok: false, error: "unsupported", message: `method ${fields.method} cannot be signed with a passkey`, ...back };
    if (fields.rp_id !== rpId)
        return { ok: false, error: "invalid-request", message: `rp_id ${fields.rp_id} is not ${rpId}`, ...back };
    const credential = q.get("credential") ?? undefined;
    const name = q.get("name") ?? undefined;
    const uv = q.get("user_verification");
    if (uv !== null && uv !== "required")
        return { ok: false, error: "invalid-request", message: `unknown user_verification ${uv}`, ...back };
    const userVerification = uv === "required" ? "required" : "preferred";
    return { ok: true, op, returnUrl, state, payload, fields, userVerification, ...(credential ? { credential } : {}), ...(name ? { name } : {}) };
}
// CLI_SPEC 8.3 check 3: a payload that names a key must name the passkey in use
export function payloadMatchesKey(fields, publicKey) {
    return fields.pubkey === undefined || fields.pubkey === "es256:" + toBase64(publicKey);
}
export function handoffResponseUrl(returnUrl, state, answer) {
    if (!isHandoffReturnUrl(returnUrl))
        throw new HandoffError("invalid-request", "the return URL must use its own scheme or a loopback address");
    const u = new URL(returnUrl);
    u.searchParams.set("v", HANDOFF_VERSION);
    u.searchParams.set("state", state);
    if ("error" in answer)
        u.searchParams.set("error", answer.error);
    else if ("rpId" in answer) {
        u.searchParams.set("rp_id", answer.rpId);
        u.searchParams.set("key", toBase64Url(answer.key));
        u.searchParams.set("credential", answer.credential);
    }
    else {
        u.searchParams.set("authenticator_data", toBase64Url(answer.authenticatorData));
        u.searchParams.set("client_data", toBase64Url(answer.clientDataJSON));
        u.searchParams.set("sig", toBase64Url(answer.signature));
    }
    return u.toString();
}
