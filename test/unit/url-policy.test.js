import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { parseTarget, classifyHost, detectSensitive, redactUrl, defang, withoutQuery, normalizeHostname, MAX_URL_LENGTH } from '../../src/shared/url-policy.js';
import { IPV4_RESERVED, IPV6_RESERVED, classifyIpLiteral, parseIPv4, parseIPv6, classifyIPv4Value, classifyIPv6Value } from '../../src/shared/ip.js';

test('audit examples: loopback, trailing dot, IPv4-mapped IPv6 (both spellings)', () => {
  const cases = {
    'http://127.0.0.1': '127.0.0.1',
    'http://localhost.': 'localhost',
    'http://[::ffff:127.0.0.1]': '[::ffff:7f00:1]',
    'http://[::ffff:7f00:1]': '[::ffff:7f00:1]'
  };
  for (const [input, host] of Object.entries(cases)) {
    const r = parseTarget(input);
    assert.equal(r.ok, true, input);
    assert.equal(r.hostname, host);
    assert.equal(r.reserved, true, input + ' must be reserved');
  }
});
test('public mapped address is classified by its embedded IPv4, not blanket-blocked', () => {
  assert.equal(parseTarget('http://[::ffff:808:808]/').reserved, false);
  assert.equal(parseTarget('http://[::ffff:10.1.2.3]/').reserved, true);
  assert.equal(parseTarget('http://[64:ff9b::7f00:1]/').reserved, true);
  assert.equal(parseTarget('http://[2002:c0a8:101::]/').reserved, true);
});
test('numeric host tricks normalize to dotted IPv4 and are classified', () => {
  for (const u of ['http://0x7f.1', 'http://2130706433/', 'http://0177.0.0.1/', 'http://127.1/']) {
    const r = parseTarget(u); assert.equal(r.ok, true, u); assert.equal(r.hostname, '127.0.0.1', u); assert.equal(r.reserved, true);
  }
});
test('reserved ranges and names', () => {
  for (const h of ['10.0.0.1', '172.16.5.5', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1', '[fe80::1]', '[fd12::1]', '[ff02::1]', '[::]', '[::1]', '[2001:db8::1]', 'localhost', 'foo.localhost', 'printer.local', 'db.internal', 'metadata.google.internal', 'router.home.arpa', 'intranet', 'a.b.test', 'x.invalid', 'x.example'])
    assert.equal(classifyHost(h).reserved, true, h);
  for (const h of ['8.8.8.8', '172.32.0.1', '1.1.1.1', '[2001:4860:4860::8888]', 'example.com', 'sub.example.co.uk'])
    assert.equal(classifyHost(h).reserved, false, h);
});
test('IP classifier agrees with node:net BlockList (differential test of the matching algorithm)', () => {
  // Oracle CIDRs are written out independently here (IANA special-purpose registries), not derived from src/.
  const V4 = [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]];
  const bl = new net.BlockList();
  for (const [a, p] of V4) bl.addSubnet(a, p, 'ipv4');
  const v4samples = ['0.1.2.3', '9.255.255.255', '10.0.0.0', '11.0.0.0', '100.63.255.255', '100.64.0.0', '100.127.255.255', '100.128.0.0', '126.255.255.255', '127.0.0.1', '128.0.0.0', '169.253.1.1', '169.254.0.1', '172.15.255.255', '172.16.0.0', '172.31.255.255', '172.32.0.0', '192.0.0.5', '192.0.2.9', '192.168.0.1', '192.167.255.255', '198.17.1.1', '198.18.0.0', '198.19.255.255', '198.20.0.0', '198.51.100.7', '203.0.113.200', '223.255.255.255', '224.0.0.0', '239.1.1.1', '240.0.0.1', '255.255.255.255', '8.8.8.8', '1.1.1.1', '93.184.216.34'];
  for (const s of v4samples) assert.equal(classifyIPv4Value(parseIPv4(s)).reserved, bl.check(s, 'ipv4'), s);

  const V6 = [['::', 128], ['::1', 128], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23], ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]];
  const bl6 = new net.BlockList();
  for (const [a, p] of V6) bl6.addSubnet(a, p, 'ipv6');
  const v6samples = ['::', '::1', '::2', '100::1', '100:0:0:1::', '2001::1', '2001:1ff::1', '2001:200::1', '2001:db8:1::1', '2001:db9::1', 'fbff::1', 'fc00::1', 'fdff::1', 'fe00::1', 'fe80::1', 'febf::1', 'fec0::1', 'feff::1', 'ff02::1', '2606:4700::1111', '2001:4860:4860::8888', '64:ff9b:1::5'];
  for (const s of v6samples) assert.equal(classifyIPv6Value(parseIPv6(s)).reserved, bl6.check(s, 'ipv6'), s);
});
test('IP parsers reject malformed literals', () => {
  for (const s of ['1.2.3', '256.1.1.1', '01.2.3.4', '1.2.3.4.5', 'a.b.c.d', '']) assert.equal(parseIPv4(s), null, s);
  for (const s of ['1::2::3', ':::', 'g::1', '1:2:3:4:5:6:7:8:9', '::1%eth0', '12345::1']) assert.equal(parseIPv6(s), null, s);
});
test('userinfo is rejected, including empty-userinfo and backslash tricks handled like a browser', () => {
  for (const u of ['https://user:pass@example.com/', 'https://user@example.com', 'http://@example.com', 'https://:@example.com']) {
    const r = parseTarget(u); assert.equal(r.ok, false, u); assert.equal(r.code, 'userinfo');
  }
  const allowed = parseTarget('https://a:b@example.com/x', { allowUserinfo: true });
  assert.equal(allowed.ok, true); assert.equal(allowed.hasUserinfo, true); assert.ok(!allowed.externalUrl.includes('a:b'));
  const bs = parseTarget('http://evil.com\\@good.com/');
  assert.equal(bs.hostname, 'evil.com', 'host is whatever the browser would connect to');
});
test('validation: schemes, whitespace, length, control characters, host:port shorthand', () => {
  assert.equal(parseTarget('').code, 'empty');
  assert.equal(parseTarget(null).code, 'empty');
  assert.equal(parseTarget('ftp://x.com').code, 'bad_scheme');
  assert.equal(parseTarget('javascript:alert(1)').code, 'bad_scheme');
  assert.equal(parseTarget('data:text/html,hi').code, 'bad_scheme');
  assert.equal(parseTarget('a'.repeat(MAX_URL_LENGTH + 1)).code, 'too_long');
  assert.equal(parseTarget('https://exa\u0000mple.com').code, 'control_chars');
  assert.equal(parseTarget('https://exa mple.com').ok, false);
  assert.equal(parseTarget('http://a..b.com').ok, false);
  assert.equal(parseTarget('example.com/x').href, 'https://example.com/x');
  assert.equal(parseTarget('example.com/x').inputHadScheme, false);
  assert.equal(parseTarget('localhost:3000/x').reserved, true);
});
test('normalization policy: fragment dropped for providers, query and path kept, default port removed', () => {
  const r = parseTarget('HTTPS://Example.COM.:443/A%20b?x=1&y=%2F#frag');
  assert.equal(r.externalUrl, 'https://example.com/A%20b?x=1&y=%2F');
  assert.equal(withoutQuery(r.externalUrl), 'https://example.com/A%20b');
  assert.equal(normalizeHostname('A.B.'), 'a.b'); assert.equal(normalizeHostname('a..b'), null); assert.equal(normalizeHostname('.'), null);
});
test('sensitive-URL detection: params, values, path flows, fragments; benign URLs not flagged', () => {
  const flagged = [
    'https://x.com/cb?access_token=abc', 'https://x.com/?api_key=1', 'https://x.com/?X-Amz-Signature=abc', 'https://x.com/?auth=zz',
    'https://x.com/?u=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123', 'https://x.com/?q=AKIAABCDEFGHIJKLMNOP',
    'https://x.com/?h=0123456789abcdef0123456789abcdef', 'https://x.com/reset/Ab3dE5gH7jK9mN1pQ2rS', 'https://x.com/?email=a@b.co',
    'https://x.com/cb#access_token=zzz&token_type=bearer', 'https://x.com/cb?code=abc&state=xyz', 'https://x.com/?sessionId=1', 'https://x.com/?my_secret=1'
  ];
  for (const u of flagged) assert.equal(detectSensitive(new URL(u)).likely, true, u);
  const ok = ['https://example.com/', 'https://example.com/search?q=cats&page=2', 'https://example.com/blog/my-first-post', 'https://example.com/?code=MY', 'https://example.com/products/12345'];
  for (const u of ok) assert.equal(detectSensitive(new URL(u)).likely, false, u);
});
test('detection reasons never include the secret value', () => {
  const secret = 'SUPERSECRETVALUE9f8e7d6c5b4a';
  const d = detectSensitive(new URL(`https://x.com/?token=${secret}&u=${secret}`));
  assert.ok(!JSON.stringify(d).includes(secret));
});
test('redaction: tokens, fragments, credentials never appear in display strings', () => {
  const secret = 'Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0';
  const u = new URL(`https://user.example.com:8443/reset/${secret}/done?token=${secret}&q=hello&jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig#access_token=${secret}`);
  const { display, redactions } = redactUrl(u);
  assert.ok(!display.includes(secret)); assert.ok(!display.includes('eyJ')); assert.ok(!display.includes('access_token'));
  assert.ok(display.includes('q=hello')); assert.ok(redactions >= 3);
  assert.ok(display.includes('#[fragment omitted]'));
  const d = defang(display); assert.ok(d.startsWith('hxxps://user[.]example[.]com'));
  assert.ok(redactUrl(new URL('https://example.com/' + 'a'.repeat(500)), 100).display.length <= 100);
});

test('redaction: a token inside a URL-valued (redirect) parameter does not leak through the outer value', () => {
  const secret = 'Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0';
  const inner = `https://t.example.net/x?token=${secret}&ok=1`;
  const outer = new URL('https://a.example.org/?u=' + encodeURIComponent(inner) + '&v=' + encodeURIComponent(encodeURIComponent(inner)));
  const { display, redactions } = redactUrl(outer);
  assert.ok(!display.includes(secret), display);
  assert.ok(redactions >= 1);
  assert.ok(display.includes('ok=1'));
});
