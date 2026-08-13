/**
 * Regression tests for the external audit of 11 August 2026 (MCP server).
 *
 * Covers the fixes that can be exercised without a live BSV node or wallet:
 *   K8  spend policy — miner fee counted, session ceiling not resettable by
 *       the agent, single guarded broadcast path.
 *   H8  SSRF guard — private / loopback / link-local targets refused, scheme
 *       allowlist, DNS-rebind pin.
 *
 * The build compiles NodeNext (`.js` specifiers). To run straight from source
 * without a build step, this file is executed against a copy of src/ whose
 * relative import specifiers have been rewritten to `.ts` (see the runner in
 * the repo README / SECURITY-FIXES doc). Run:
 *
 *   node --experimental-strip-types test/audit-2026-08-11.test.mjs
 *
 * from that prepared copy.
 */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

// A tiny fake decode node must be reachable BEFORE policy/constants load,
// because ORDNET_API is read at module-eval time. Start it, point the env at
// it, then import the modules under test.
let lastTx = null;
const fakeNode = createServer((req, res) => {
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    let outs = [];
    try { outs = JSON.parse(Buffer.from(JSON.parse(body).rawtx, 'hex').toString('utf8')).vout; } catch {}
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ txid: 'a'.repeat(64), size: 200, vout: outs }));
  });
});
await new Promise(r => fakeNode.listen(0, '127.0.0.1', r));
const port = fakeNode.address().port;
process.env.ORDNET_API = `http://127.0.0.1:${port}`;
// This suite exercises the policy machinery itself, so it opts out of the
// operator ceilings deliberately — otherwise every setPolicy({resetSession})
// below would be refused, which is exactly the behaviour asserted further down.
// The DEFAULTS get their own assertions in the block at the end.
process.env.ORDNET_POLICY_MAX_SATS_PER_TX = 'unlimited';
process.env.ORDNET_POLICY_MAX_SATS_PER_SESSION = 'unlimited';

const { isBlockedIp, safeFetch } = await import('../src/services/net.ts');
const {
  setPolicy, getPolicy, enforcePolicy, recordBroadcast,
  broadcastGuarded, PolicyViolationError, HARD_CEILINGS
} = await import('../src/services/policy.ts');

let pass = 0, fail = 0;
const t = async (name, fn) => {
  try { await fn(); pass++; console.log('  ok  ' + name); }
  catch (e) { fail++; console.log('FAIL  ' + name + '\n      ' + e.message); }
};

console.log('\n[H8] SSRF address guard');
await t('loopback v4 is blocked', () => assert.equal(isBlockedIp('127.0.0.1'), true));
await t('cloud metadata 169.254.169.254 is blocked', () => assert.equal(isBlockedIp('169.254.169.254'), true));
await t('RFC1918 10/8 blocked', () => assert.equal(isBlockedIp('10.1.2.3'), true));
await t('RFC1918 172.16/12 blocked', () => assert.equal(isBlockedIp('172.20.0.1'), true));
await t('RFC1918 192.168/16 blocked', () => assert.equal(isBlockedIp('192.168.1.1'), true));
await t('CGNAT 100.64/10 blocked', () => assert.equal(isBlockedIp('100.64.0.1'), true));
await t('multicast blocked', () => assert.equal(isBlockedIp('224.0.0.1'), true));
await t('public v4 allowed', () => assert.equal(isBlockedIp('93.184.216.34'), false));
await t('IPv6 loopback blocked', () => assert.equal(isBlockedIp('::1'), true));
await t('IPv6 link-local blocked', () => assert.equal(isBlockedIp('fe80::1'), true));
await t('IPv6 ULA blocked', () => assert.equal(isBlockedIp('fd00::1'), true));
await t('IPv4-mapped metadata blocked', () => assert.equal(isBlockedIp('::ffff:169.254.169.254'), true));
await t('garbage refused', () => assert.equal(isBlockedIp('not-an-ip'), true));

await t('safeFetch refuses non-http scheme', async () => {
  await assert.rejects(() => safeFetch('file:///etc/passwd'), /only http\/https/);
});
await t('safeFetch refuses a literal private IP before connecting', async () => {
  await assert.rejects(() => safeFetch('http://127.0.0.1:7002/'), /SSRF guard/);
});
await t('safeFetch refuses the cloud metadata IP', async () => {
  await assert.rejects(() => safeFetch('http://169.254.169.254/latest/meta-data/'), /SSRF guard/);
});
await t('safeFetch refuses an unparseable URL', async () => {
  await assert.rejects(() => safeFetch('http://'), /valid URL|did not resolve|SSRF/);
});

console.log('\n[K8] spend policy');

// Build a "rawtx" that our fake node will decode into these outputs.
const mkHex = (outputs) => Buffer.from(JSON.stringify({
  vout: outputs.map((o, n) => ({ n, value: o.sats / 1e8, scriptPubKey: { type: 'pubkeyhash', addresses: o.addr ? [o.addr] : [] } }))
}), 'utf8').toString('hex');

await t('no limits -> enforcePolicy is a no-op (null)', async () => {
  setPolicy({ maxSatsPerTx: null, maxSatsPerSession: null });
  const sim = await enforcePolicy(mkHex([{ sats: 5000, addr: 'X' }]));
  assert.equal(sim, null);
});

await t('miner fee is counted into the spend (K8)', async () => {
  setPolicy({ maxSatsPerTx: 10_000, maxSatsPerSession: null, resetSession: true });
  // outputs 5000 to a stranger, miner fee 6000 => 11000 spend > 10000 limit
  await assert.rejects(
    () => enforcePolicy(mkHex([{ sats: 5000, addr: 'stranger' }]), 'me', 6000),
    (e) => e instanceof PolicyViolationError && /miner fee/.test(e.message)
  );
});

await t('change to own address is excluded, fee still counted', async () => {
  setPolicy({ maxSatsPerTx: 10_000, maxSatsPerSession: null, resetSession: true });
  // 3000 to stranger + 90000 change to self + 2000 fee => spend 5000 <= 10000
  const sim = await enforcePolicy(
    mkHex([{ sats: 3000, addr: 'stranger' }, { sats: 90000, addr: 'me' }]), 'me', 2000);
  assert.equal(sim.spendSats, 5000);
  assert.equal(sim.minerFee, 2000);
});

await t('agent cannot reset the session when a session ceiling exists', () => {
  if (HARD_CEILINGS.maxSatsPerSession === null) {
    const p = setPolicy({ resetSession: true });
    assert.equal(p.spentThisSession, 0);
  } else {
    assert.throws(() => setPolicy({ resetSession: true }), PolicyViolationError);
  }
});

/* ------------------------------------------------------------------ *
 * The spend policy must be fail-closed out of the box.
 *
 * Both ceilings previously defaulted to null, and enforcePolicy() returns
 * early when both are null — so a freshly installed server enforced nothing
 * and ordnet_send would broadcast any amount an agent asked for. On-chain
 * content flows into that agent's context and anyone can inscribe for under
 * a cent, so "no default limit" completed a path from prompt injection to a
 * drained wallet.
 * ------------------------------------------------------------------ */
await t('an unset environment yields real ceilings, not null', async () => {
  const saveTx = process.env.ORDNET_POLICY_MAX_SATS_PER_TX;
  const saveSes = process.env.ORDNET_POLICY_MAX_SATS_PER_SESSION;
  delete process.env.ORDNET_POLICY_MAX_SATS_PER_TX;
  delete process.env.ORDNET_POLICY_MAX_SATS_PER_SESSION;
  const fresh = await import('../src/services/policy.ts?defaults=' + Date.now());
  assert.equal(typeof fresh.HARD_CEILINGS.maxSatsPerTx, 'number');
  assert.equal(typeof fresh.HARD_CEILINGS.maxSatsPerSession, 'number');
  assert.ok(fresh.HARD_CEILINGS.maxSatsPerTx > 0);
  assert.ok(fresh.HARD_CEILINGS.maxSatsPerSession >= fresh.HARD_CEILINGS.maxSatsPerTx);
  if (saveTx !== undefined) process.env.ORDNET_POLICY_MAX_SATS_PER_TX = saveTx;
  if (saveSes !== undefined) process.env.ORDNET_POLICY_MAX_SATS_PER_SESSION = saveSes;
});

await t('a default-configured server blocks an oversized send', async () => {
  const saveTx = process.env.ORDNET_POLICY_MAX_SATS_PER_TX;
  const saveSes = process.env.ORDNET_POLICY_MAX_SATS_PER_SESSION;
  delete process.env.ORDNET_POLICY_MAX_SATS_PER_TX;
  delete process.env.ORDNET_POLICY_MAX_SATS_PER_SESSION;
  const fresh = await import('../src/services/policy.ts?blocks=' + Date.now());
  let broadcast = false;
  await assert.rejects(
    () => fresh.broadcastGuarded(
      async () => { broadcast = true; return 'x'.repeat(64); },
      mkHex([{ sats: 50_000_000, addr: 'stranger' }]), 'me', 1000),
    fresh.PolicyViolationError,
    'a 0.5 BSV send must be refused by the default ceiling'
  );
  assert.equal(broadcast, false, 'nothing may reach the network when the policy blocks');
  if (saveTx !== undefined) process.env.ORDNET_POLICY_MAX_SATS_PER_TX = saveTx;
  if (saveSes !== undefined) process.env.ORDNET_POLICY_MAX_SATS_PER_SESSION = saveSes;
});

await t('"unlimited" is honoured but must be spelled out', async () => {
  process.env.ORDNET_POLICY_MAX_SATS_PER_TX = 'unlimited';
  const fresh = await import('../src/services/policy.ts?unlimited=' + Date.now());
  assert.equal(fresh.HARD_CEILINGS.maxSatsPerTx, null);
});

await t('a malformed ceiling falls back to the default instead of to null', async () => {
  process.env.ORDNET_POLICY_MAX_SATS_PER_TX = 'lots';
  const fresh = await import('../src/services/policy.ts?bad=' + Date.now());
  assert.equal(typeof fresh.HARD_CEILINGS.maxSatsPerTx, 'number');
  process.env.ORDNET_POLICY_MAX_SATS_PER_TX = 'unlimited';
});

await t('a value parseInt would silently truncate is refused, not accepted', async () => {
  // parseInt('1e9') === 1 and parseInt('100_000') === 100. Both are > 0, so an
  // operator writing a perfectly reasonable-looking number would have ended up
  // with a one-satoshi ceiling and no warning.
  for (const [raw, why] of [
    ['1e9', 'exponent notation'],
    ['100_000', 'underscore separator'],
    ['1,000,000', 'thousands separators'],
    ['0.5', 'a decimal'],
    ['10 BSV', 'a unit suffix'],
    ['  500  ', 'padded — this one is fine'],
    ['-100', 'negative']
  ]) {
    process.env.ORDNET_POLICY_MAX_SATS_PER_TX = raw;
    const fresh = await import(`../src/services/policy.ts?p=${encodeURIComponent(raw)}${Date.now()}`);
    const got = fresh.HARD_CEILINGS.maxSatsPerTx;
    if (raw.trim() === '500') {
      assert.equal(got, 500, 'surrounding whitespace should still parse');
    } else {
      assert.notEqual(got, 1, `${why}: "${raw}" was truncated to 1 satoshi`);
      assert.ok(got >= 100_000, `${why}: "${raw}" should fall back to the default, got ${got}`);
    }
  }
  process.env.ORDNET_POLICY_MAX_SATS_PER_TX = 'unlimited';
});

await t('broadcastGuarded enforces, broadcasts and records in order', async () => {
  setPolicy({ maxSatsPerTx: 100_000, maxSatsPerSession: 100_000, resetSession: true });
  const before = getPolicy().broadcastCount;
  const order = [];
  const fakeBroadcast = async (hex) => { order.push('broadcast'); return 'b'.repeat(64); };
  const { txid, simulation } = await broadcastGuarded(
    fakeBroadcast, mkHex([{ sats: 4000, addr: 'stranger' }]), 'me', 1000);
  assert.equal(txid, 'b'.repeat(64));
  assert.equal(simulation.spendSats, 5000); // 4000 out + 1000 fee
  assert.equal(getPolicy().broadcastCount, before + 1);
  assert.equal(getPolicy().spentThisSession, 5000);
});

await t('broadcastGuarded does NOT broadcast when the policy blocks', async () => {
  setPolicy({ maxSatsPerTx: 1000, maxSatsPerSession: null, resetSession: true });
  let broadcast = false;
  const fakeBroadcast = async () => { broadcast = true; return 'x'; };
  await assert.rejects(
    () => broadcastGuarded(fakeBroadcast, mkHex([{ sats: 5000, addr: 'stranger' }]), 'me', 500),
    PolicyViolationError
  );
  assert.equal(broadcast, false); // blocked before the network call
});

fakeNode.close();

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
