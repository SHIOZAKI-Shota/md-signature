import { bytesEqual, toHex } from "./encoding.js";
import { parseDer } from "./der.js";
import { OID, buildPath, derSet, oidString, parseAlgId, parseCertificate, pemToDer, shaDigest, shaName, verifyWithCert } from "./x509.js";
import { DEFAULT_TSA_ROOTS } from "./tsa-roots.js";
// --- RFC 5652 SignedData as used by RFC 3161
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TSTINFO = "1.2.840.113549.1.9.16.1.4";
const OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_ATTR_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12";
const OID_ATTR_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47";
// for UIs that let a user add roots: what each certificate in the input is
export async function readTsaRoots(input) {
    const out = [];
    for (const der of pemToDer(input)) {
        const c = parseCertificate(der);
        out.push({ name: c.name, sha256: toHex(await shaDigest("SHA-256", c.raw)), notAfter: new Date(c.notAfter).toISOString().slice(0, 10), der: c.raw });
    }
    return out;
}
let defaultRoots;
function parseRoots(list, option) {
    return list.flatMap((r, i) => {
        try {
            return pemToDer(r).map(parseCertificate);
        }
        catch (e) {
            throw new Error(`${option}[${i}] is not a certificate: ${e.message}`);
        }
    });
}
function trustAnchors(o) {
    const base = o.roots ? parseRoots(o.roots, "tsaRoots") : (defaultRoots ??= DEFAULT_TSA_ROOTS.map((r) => parseCertificate(r.der)));
    return o.extraRoots?.length ? [...base, ...parseRoots(o.extraRoots, "extraTsaRoots")] : base;
}
function attrValue(attrs, oid) {
    const a = attrs.find((x) => x.type === oid);
    if (!a)
        return undefined;
    if (a.values.tag !== 0x31 || a.values.children?.length !== 1)
        throw new Error(`signed attribute ${oid} must have exactly one value`);
    return a.values.children[0];
}
function stripZeros(b) {
    let v = b;
    while (v.length > 1 && v[0] === 0)
        v = v.subarray(1);
    return v;
}
function findSignerCert(sid, certs) {
    // [0] IMPLICIT SubjectKeyIdentifier
    if (sid.tag === 0x80)
        return certs.find((c) => c.subjectKeyId?.length && bytesEqual(c.subjectKeyId, sid.content));
    const [issuer, serial] = sid.children ?? [];
    if (sid.tag !== 0x30 || !issuer || serial?.tag !== 0x02)
        return undefined;
    return certs.find((c) => bytesEqual(c.issuerRaw, issuer.bytes) && bytesEqual(c.serial, stripZeros(serial.content)));
}
// RFC 3161 2.4.2 / RFC 5816: the first ESSCertID(v2) names the certificate that signed the token
async function checkSigningCertAttr(attrs, cert) {
    const v2 = attrValue(attrs, OID_ATTR_SIGNING_CERT_V2);
    const v1 = attrValue(attrs, OID_ATTR_SIGNING_CERT);
    if (!v1 && !v2)
        throw new Error("no signing-certificate attribute");
    const first = (v) => {
        const id = v.children?.[0]?.children?.[0];
        if (!id || id.tag !== 0x30)
            throw new Error("signing-certificate attribute is malformed");
        return id;
    };
    const mismatch = () => new Error("signing-certificate attribute does not match the TSA certificate");
    if (v2) {
        const id = first(v2);
        let hashNode = id.children?.[0];
        let h = shaName(OID.sha256);
        if (hashNode?.tag === 0x30) {
            const alg = parseAlgId(hashNode).oid;
            const named = shaName(alg);
            if (!named)
                throw new Error(`signing-certificate hash ${alg} is not supported`);
            h = named;
            hashNode = id.children?.[1];
        }
        if (hashNode?.tag !== 0x04 || !bytesEqual(hashNode.content, await shaDigest(h, cert.raw)))
            throw mismatch();
    }
    if (v1) {
        // ESSCertID is defined with SHA-1; it only binds the certificate that the signature already names
        const h = first(v1).children?.[0];
        if (h?.tag !== 0x04 || !bytesEqual(h.content, await shaDigest("SHA-1", cert.raw)))
            throw mismatch();
    }
}
// verifies the token's CMS signature and certificate chain; returns the authenticated eContent and the TSA certificate
export async function verifyTsaSignedData(token, genTime, o = {}) {
    const { node: ci, next } = parseDer(token);
    const ciType = ci.children?.[0];
    if (ci.tag !== 0x30 || next !== token.length || ciType?.tag !== 0x06)
        throw new Error("token is not DER-encoded CMS");
    if (oidString(ciType.content) !== OID_SIGNED_DATA)
        throw new Error("token is not CMS SignedData");
    const sd = ci.children[1]?.tag === 0xa0 ? ci.children[1].children?.[0] : undefined;
    const f = sd?.children ?? [];
    const encap = f[2];
    if (sd?.tag !== 0x30 || f[0]?.tag !== 0x02 || f[1]?.tag !== 0x31 || encap?.tag !== 0x30)
        throw new Error("SignedData is not valid DER");
    const tail = f.slice(3);
    const certSet = tail[0]?.tag === 0xa0 ? tail.shift() : undefined;
    if (tail[0]?.tag === 0xa1)
        tail.shift();
    const signerInfos = tail[0];
    if (signerInfos?.tag !== 0x31 || tail.length !== 1)
        throw new Error("SignedData is not valid DER");
    const eType = encap.children?.[0];
    if (eType?.tag !== 0x06 || oidString(eType.content) !== OID_TSTINFO)
        throw new Error("content type is not id-ct-TSTInfo");
    const octets = encap.children?.[1]?.tag === 0xa0 ? encap.children[1].children?.[0] : undefined;
    if (octets?.tag !== 0x04 || !octets.content.length)
        throw new Error("eContent is missing");
    const eContent = octets.content;
    if (signerInfos.children?.length !== 1)
        throw new Error(`token has ${signerInfos.children?.length ?? 0} SignerInfos, want exactly 1`);
    const si = [...(signerInfos.children[0].children ?? [])];
    const [version, sid, digestAlgNode] = si.splice(0, 3);
    const signedAttrs = si[0]?.tag === 0xa0 ? si.shift() : undefined;
    const [sigAlgNode, sigNode] = si;
    if (version?.tag !== 0x02 || !sid || !digestAlgNode || !sigAlgNode || sigNode?.tag !== 0x04)
        throw new Error("SignerInfo is not valid DER");
    const certs = [];
    for (const c of certSet?.children ?? []) {
        // other CertificateChoices (attribute certificates) and unparsable entries are skipped
        if (c.tag !== 0x30)
            continue;
        try {
            certs.push(parseCertificate(c.bytes));
        }
        catch { }
    }
    const cert = findSignerCert(sid, certs);
    if (!cert)
        throw new Error("TSA certificate is not included in the token");
    const digestOid = parseAlgId(digestAlgNode).oid;
    const digestHash = shaName(digestOid);
    if (!digestHash)
        throw new Error(`digest algorithm ${digestOid} is not SHA-256, SHA-384, or SHA-512`);
    // RFC 3161 2.4.2 requires the signing-certificate attribute, so a token without signed attributes is rejected
    if (!signedAttrs?.children?.length)
        throw new Error("token has no signed attributes");
    const attrs = [];
    for (const a of signedAttrs.children) {
        const [t, values] = a.children ?? [];
        if (a.tag !== 0x30 || t?.tag !== 0x06 || !values || a.children.length !== 2)
            throw new Error("signed attribute is not valid DER");
        const type = oidString(t.content);
        if (attrs.some((x) => x.type === type))
            throw new Error(`signed attribute ${type} appears twice`);
        attrs.push({ type, values });
    }
    const ct = attrValue(attrs, OID_ATTR_CONTENT_TYPE);
    if (!ct)
        throw new Error("signed attributes have no content-type");
    if (ct.tag !== 0x06 || oidString(ct.content) !== OID_TSTINFO)
        throw new Error("signed content-type is not id-ct-TSTInfo");
    const md = attrValue(attrs, OID_ATTR_MESSAGE_DIGEST);
    if (!md)
        throw new Error("signed attributes have no message-digest");
    if (md.tag !== 0x04 || !bytesEqual(md.content, await shaDigest(digestHash, eContent)))
        throw new Error("message-digest does not match the TSTInfo");
    await checkSigningCertAttr(attrs, cert);
    // RFC 5652 5.4: the signature covers the DER SET OF (tag 0x31, elements sorted), not the [0] IMPLICIT encoding
    const signed = derSet(signedAttrs.children.map((a) => a.bytes));
    if (!(await verifyWithCert(cert, parseAlgId(sigAlgNode), digestHash, signed, sigNode.content)))
        throw new Error("signature does not verify with the TSA certificate");
    if (!cert.eku?.includes(OID.ekuTimeStamping))
        throw new Error("TSA certificate lacks the timeStamping extended key usage");
    if (genTime < cert.notBefore || genTime > cert.notAfter)
        throw new Error("TSA certificate was not valid at the token's time");
    // a wrong option is the caller's mistake and is reported as such, not as an untrusted chain
    const roots = trustAnchors(o);
    try {
        // a timestamp stays valid after the TSA certificate expires, so the chain is checked at genTime
        await buildPath(cert, { roots, intermediates: certs.filter((c) => c !== cert), at: genTime, eku: OID.ekuTimeStamping });
    }
    catch (e) {
        throw new Error(`TSA certificate does not chain to a trusted root: ${e.message}`);
    }
    return { eContent, cert };
}
