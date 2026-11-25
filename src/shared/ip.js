// IP literal parsing and special-purpose-range classification.
// Isomorphic (browser + Node). Operates on *canonical* hosts produced by the WHATWG URL
// parser (dotted-quad IPv4, bracketed compressed IPv6), but also accepts raw forms.
// Ranges come from the IANA IPv4/IPv6 Special-Purpose Address Registries.
// This module classifies address *literals*; it does NOT resolve DNS. Hostname checks alone
// are insufficient for any feature that fetches user-supplied targets (see README).

export function parseIPv4(s) {
  if (typeof s !== 'string') return null;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  let v = 0n;
  for (let i = 1; i <= 4; i++) {
    if (m[i].length > 1 && m[i][0] === '0') return null; // reject ambiguous octal-looking octets
    const n = Number(m[i]);
    if (n > 255) return null;
    v = (v << 8n) | BigInt(n);
  }
  return v;
}

export function formatIPv4(v) {
  return [24n, 16n, 8n, 0n].map((sh) => String((v >> sh) & 0xffn)).join('.');
}

export function parseIPv6(input) {
  if (typeof input !== 'string') return null;
  let s = input;
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (!s || s.includes('%') || /[^0-9a-fA-F:.]/.test(s)) return null; // zone ids rejected
  let tail = null;
  const lastColon = s.lastIndexOf(':');
  if (s.includes('.')) {
    const v4 = parseIPv4(s.slice(lastColon + 1));
    if (v4 === null) return null;
    tail = [Number((v4 >> 16n) & 0xffffn), Number(v4 & 0xffffn)];
    s = s.slice(0, lastColon + 1) + '0:0';
  }
  const dbl = s.split('::');
  if (dbl.length > 2) return null;
  const toGroups = (part) => (part === '' ? [] : part.split(':'));
  const head = toGroups(dbl[0]);
  const rest = dbl.length === 2 ? toGroups(dbl[1]) : [];
  const all = head.concat(rest);
  if (all.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  let groups;
  if (dbl.length === 2) {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    groups = head.concat(Array(missing).fill('0'), rest);
  } else {
    if (head.length !== 8) return null;
    groups = head;
  }
  const nums = groups.map((g) => parseInt(g, 16));
  if (tail) { nums[6] = tail[0]; nums[7] = tail[1]; }
  let v = 0n;
  for (const n of nums) v = (v << 16n) | BigInt(n);
  return v;
}

const v4 = (cidr, why) => { const [a, p] = cidr.split('/'); return { base: parseIPv4(a), bits: Number(p), why, fam: 4 }; };
const v6 = (cidr, why, embed) => { const [a, p] = cidr.split('/'); return { base: parseIPv6(a), bits: Number(p), why, fam: 6, embed }; };

export const IPV4_RESERVED = [
  v4('0.0.0.0/8', 'this-network (0.0.0.0/8)'),
  v4('10.0.0.0/8', 'private (10.0.0.0/8)'),
  v4('100.64.0.0/10', 'carrier-grade NAT (100.64.0.0/10)'),
  v4('127.0.0.0/8', 'loopback (127.0.0.0/8)'),
  v4('169.254.0.0/16', 'link-local / cloud metadata (169.254.0.0/16)'),
  v4('172.16.0.0/12', 'private (172.16.0.0/12)'),
  v4('192.0.0.0/24', 'IETF protocol assignments (192.0.0.0/24)'),
  v4('192.0.2.0/24', 'documentation TEST-NET-1'),
  v4('192.88.99.0/24', 'deprecated 6to4 relay anycast'),
  v4('192.168.0.0/16', 'private (192.168.0.0/16)'),
  v4('198.18.0.0/15', 'benchmarking (198.18.0.0/15)'),
  v4('198.51.100.0/24', 'documentation TEST-NET-2'),
  v4('203.0.113.0/24', 'documentation TEST-NET-3'),
  v4('224.0.0.0/4', 'multicast (224.0.0.0/4)'),
  v4('240.0.0.0/4', 'reserved / broadcast (240.0.0.0/4)')
];

export const IPV6_RESERVED = [
  v6('::/128', 'unspecified address'),
  v6('::1/128', 'loopback'),
  v6('::ffff:0:0/96', 'IPv4-mapped', 'low32'),
  v6('64:ff9b::/96', 'NAT64 well-known prefix', 'low32'),
  v6('64:ff9b:1::/48', 'local-use NAT64'),
  v6('100::/64', 'discard-only'),
  v6('2001::/23', 'IETF protocol assignments (incl. Teredo)'),
  v6('2001:db8::/32', 'documentation'),
  v6('2002::/16', '6to4 (embeds an IPv4 address)', 'sixtofour'),
  v6('fc00::/7', 'unique local (fc00::/7)'),
  v6('fe80::/10', 'link-local (fe80::/10)'),
  v6('fec0::/10', 'deprecated site-local (fec0::/10)'),
  v6('ff00::/8', 'multicast (ff00::/8)')
];

function inRange(value, range, width) {
  const shift = BigInt(width - range.bits);
  return (value >> shift) === (range.base >> shift);
}

export function classifyIPv4Value(value) {
  for (const r of IPV4_RESERVED) if (inRange(value, r, 32)) return { reserved: true, reason: r.why };
  return { reserved: false, reason: null };
}

export function classifyIPv6Value(value) {
  for (const r of IPV6_RESERVED) {
    if (!inRange(value, r, 128)) continue;
    if (r.embed === 'low32' || r.embed === 'sixtofour') {
      const embedded = r.embed === 'low32' ? (value & 0xffffffffn) : ((value >> 80n) & 0xffffffffn);
      const inner = classifyIPv4Value(embedded);
      if (inner.reserved) return { reserved: true, reason: `${r.why} wrapping ${inner.reason}` };
      // A public IPv4 wrapped in a mapped/NAT64/6to4 literal is classified by the embedded address.
      return { reserved: false, reason: null, embeddedIPv4: formatIPv4(embedded) };
    }
    return { reserved: true, reason: r.why };
  }
  return { reserved: false, reason: null };
}

/** Classify a host literal. Returns { kind: 'ipv4'|'ipv6'|null, reserved, reason }. */
export function classifyIpLiteral(host) {
  if (typeof host !== 'string') return { kind: null, reserved: false, reason: null };
  const h = host;
  const a = parseIPv4(h);
  if (a !== null) return { kind: 'ipv4', ...classifyIPv4Value(a) };
  const b = parseIPv6(h);
  if (b !== null) return { kind: 'ipv6', ...classifyIPv6Value(b) };
  return { kind: null, reserved: false, reason: null };
}
