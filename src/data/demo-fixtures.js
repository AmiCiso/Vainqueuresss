// DEMONSTRATION FIXTURES ONLY.
// These hard-coded entries exist so the preset buttons and tests have something deterministic to
// match. They are NOT sourced from a verified, fresh threat feed and must never be presented as
// evidence of a real, active campaign. Provenance: authored by the VAINQUEURES maintainers as
// synthetic/educational examples. No freshness guarantee. Not updated automatically.
export const FIXTURE_PROVENANCE = 'Hard-coded demonstration fixtures (synthetic, unverified, not kept fresh).';

export const DEMO_FIXTURES = [
  { type: 'host-exact', value: 'register.ap-my1.com', note: 'synthetic regional-decoy example' },
  { type: 'host-exact', value: 'ap-my1.com', note: 'synthetic regional-decoy example' },
  { type: 'host-contains', value: 'cimbcllcks', note: 'synthetic typosquat example' },
  { type: 'host-exact', value: '185.220.101.5', note: 'example raw-IP host used by the preset button' }
];

export function matchDemoFixture(hostname) {
  return DEMO_FIXTURES.find((f) => (f.type === 'host-exact' ? hostname === f.value : hostname.includes(f.value))) || null;
}
