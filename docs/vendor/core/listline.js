// --- List-form lines (SPEC 3.5): target *(SP attr), attr = name ["=" value]
const ATTR_NAME_RE = /^[a-z][a-z0-9_]*$/;
export function parseListLine(raw, known) {
    const indent = raw.length - raw.replace(/^ +/, "").length;
    const text = raw.slice(indent);
    if (!text)
        return { error: "empty line" };
    const parts = text.split(" ");
    // SPEC 3.5: exactly one SP between items
    if (parts.some((p) => p === ""))
        return { error: `items must be separated by exactly one space: ${JSON.stringify(raw)}` };
    // SPEC 3.5: the first item is always the target and may contain "="
    const [target, ...rest] = parts;
    const attrs = new Map();
    const unknown = [];
    for (const p of rest) {
        const eq = p.indexOf("=");
        const name = eq < 0 ? p : p.slice(0, eq);
        const value = eq < 0 ? true : p.slice(eq + 1);
        if (!ATTR_NAME_RE.test(name))
            return { error: `invalid attribute ${JSON.stringify(p)}` };
        if (attrs.has(name))
            return { error: `attribute "${name}" appears twice` };
        if (value === "")
            return { error: `attribute "${name}" has an empty value` };
        const kind = known[name];
        if (kind === "value" && value === true)
            return { error: `attribute "${name}" needs a value` };
        if (kind === "flag" && value !== true)
            return { error: `attribute "${name}" takes no value` };
        if (!kind)
            unknown.push(name);
        attrs.set(name, value);
    }
    return { line: { indent, target, attrs, unknown } };
}
