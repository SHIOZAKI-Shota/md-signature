export interface Der {
  tag: number;
  bytes: Uint8Array;
  content: Uint8Array;
  children?: Der[];
}

// a real TimeStampResp nests about 10 levels
const MAX_DER_DEPTH = 32;

export function parseDer(b: Uint8Array, offset = 0, depth = 0): { node: Der; next: number } {
  if (depth > MAX_DER_DEPTH) throw new Error("DER: nested too deeply");
  if (offset + 2 > b.length) throw new Error("DER: truncated");
  const tag = b[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new Error("DER: multi-byte tags not supported");
  let len = b[offset + 1]!;
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("DER: bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[offset + 2 + i]!;
    hdr += n;
  }
  const start = offset + hdr;
  const end = start + len;
  if (end > b.length) throw new Error("DER: length exceeds data");
  const content = b.subarray(start, end);
  const node: Der = { tag, bytes: b.subarray(offset, end), content };
  if (tag & 0x20) {
    node.children = [];
    let o = 0;
    while (o < content.length) {
      const r = parseDer(content, o, depth + 1);
      node.children.push(r.node);
      o = r.next;
    }
  }
  return { node, next: end };
}
