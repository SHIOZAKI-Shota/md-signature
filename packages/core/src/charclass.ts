// --- character classes (internal)

// SPEC 3.2 rule 4: Cc, Cf, Zl, Zp of Unicode 15.0.0 (pinned so TS and Go agree whatever the runtime's Unicode version), and surrogates
export const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891\u08e2\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb\u{110bd}\u{110cd}\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\u{e0001}\u{e0020}-\u{e007f}\p{Cs}]/u;

export function hasNoncharacter(s: string): boolean {
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if ((cp >= 0xfdd0 && cp <= 0xfdef) || (cp & 0xfffe) === 0xfffe) return true;
  }
  return false;
}
