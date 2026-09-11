/**
 * Tests for the reference backend.
 *
 * The verification rules in spec 9.2 are the kind that look fine until someone actually tries
 * them, so each one gets a test that would fail if the rule were removed.
 */

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, test } from 'node:test';

import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';

import {
  DEFAULT_RATE_LIMIT,
  InMemoryPepperStore,
  ReleaseLimiter,
} from './pepper.ts';
import { createHandler } from './server.ts';
import { TokenVerifier, VerificationError, requireFreshAuth } from './verify.ts';

const ISSUER = 'https://host.example';
const AUDIENCE = 'https://miniapp.example';

let jwksServer: ReturnType<typeof createServer>;
let jwksUri: URL;
type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let signingKey: PrivateKey;
let otherKey: PrivateKey;

before(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  const other = await generateKeyPair('RS256', { extractable: true });
  signingKey = pair.privateKey;
  otherKey = other.privateKey;

  const jwk: JWK = { ...(await exportJWK(pair.publicKey)), kid: 'test-key', alg: 'RS256' };

  jwksServer = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise<void>((r) => jwksServer.listen(0, '127.0.0.1', r));
  jwksUri = new URL(`http://127.0.0.1:${(jwksServer.address() as AddressInfo).port}/jwks`);
});

after(() => jwksServer.close());

function verifier() {
  return new TokenVerifier({
    jwksUri,
    algorithms: ['RS256'],
    issuers: [ISSUER],
    audiences: [AUDIENCE],
  });
}

async function token(
  overrides: { iss?: string; aud?: string; exp?: string | number; authTime?: number } = {},
  key: PrivateKey = signingKey,
) {
  let jwt = new SignJWT({
    ...(overrides.authTime === undefined ? {} : { auth_time: overrides.authTime }),
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setSubject('user-123')
    .setIssuer(overrides.iss ?? ISSUER)
    .setAudience(overrides.aud ?? AUDIENCE)
    .setIssuedAt();
  jwt = jwt.setExpirationTime(overrides.exp ?? '5m');
  return jwt.sign(key);
}

describe('TokenVerifier configuration', () => {
  test('refuses an empty algorithm allowlist', () => {
    assert.throws(
      () => new TokenVerifier({ jwksUri, algorithms: [], issuers: [ISSUER], audiences: [AUDIENCE] }),
      /non-empty allowlist/,
    );
  });

  test("refuses 'none'", () => {
    assert.throws(
      () =>
        new TokenVerifier({
          jwksUri,
          algorithms: ['none'],
          issuers: [ISSUER],
          audiences: [AUDIENCE],
        }),
      /not a signing algorithm/,
    );
  });

  /** Accepting HMAC against a JWKS *is* the RS256->HS256 confusion attack, by configuration. */
  test('refuses HMAC algorithms', () => {
    assert.throws(
      () =>
        new TokenVerifier({
          jwksUri,
          algorithms: ['RS256', 'HS256'],
          issuers: [ISSUER],
          audiences: [AUDIENCE],
        }),
      /HMAC algorithms cannot be verified against a JWKS/,
    );
  });

  test('requires issuer and audience allowlists', () => {
    assert.throws(
      () => new TokenVerifier({ jwksUri, algorithms: ['RS256'], issuers: [], audiences: [AUDIENCE] }),
      /issuers/,
    );
    assert.throws(
      () => new TokenVerifier({ jwksUri, algorithms: ['RS256'], issuers: [ISSUER], audiences: [] }),
      /audiences/,
    );
  });
});

describe('TokenVerifier', () => {
  test('accepts a valid token and returns the subject', async () => {
    const result = await verifier().verify(await token());
    assert.equal(result.sub, 'user-123');
  });

  test('rejects a token signed by the wrong key', async () => {
    const forged = await token({}, otherKey);
    await assert.rejects(
      () => verifier().verify(forged),
      (e: Error) => e instanceof VerificationError,
    );
  });

  test('rejects the wrong issuer', async () => {
    const bad = await token({ iss: 'https://evil.example' });
    await assert.rejects(() => verifier().verify(bad));
  });

  /** A token minted for a different audience is someone else's; accepting it is confused deputy. */
  test('rejects the wrong audience', async () => {
    const bad = await token({ aud: 'https://evil.example' });
    await assert.rejects(() => verifier().verify(bad));
  });

  test('rejects an expired token', async () => {
    const expired = await token({ exp: '-1h' });
    await assert.rejects(() => verifier().verify(expired));
  });

  test('surfaces auth_time when the host publishes it', async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifier().verify(await token({ authTime: now - 30 }));
    assert.equal(result.authTime, now - 30);
    requireFreshAuth(result, 300, now);
  });

  test('requireFreshAuth rejects a stale authentication', async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifier().verify(await token({ authTime: now - 3600 }));
    assert.throws(
      () => requireFreshAuth(result, 300, now),
      (e: Error) => e instanceof VerificationError && e.reason === 'stale_auth',
    );
  });

  /** Without auth_time, freshness cannot be claimed - and must not be silently assumed. */
  test('requireFreshAuth refuses when auth_time is absent', async () => {
    const result = await verifier().verify(await token());
    assert.throws(
      () => requireFreshAuth(result, 300),
      (e: Error) => e instanceof VerificationError && e.reason === 'freshness_unavailable',
    );
  });
});

describe('ReleaseLimiter', () => {
  test('allows up to the window limit, then blocks', () => {
    const limiter = new ReleaseLimiter({ ...DEFAULT_RATE_LIMIT, maxPerWindow: 3 });
    for (let i = 0; i < 3; i++) {
      assert.equal(limiter.check('u', true).allow, true);
      limiter.record('u');
    }
    const blocked = limiter.check('u', true);
    assert.equal(blocked.allow, false);
    assert.equal(blocked.allow === false && blocked.reason, 'rate_limited');
  });

  test('the window rolls forward', () => {
    const limiter = new ReleaseLimiter({ ...DEFAULT_RATE_LIMIT, maxPerWindow: 1, windowMs: 1000 });
    limiter.record('u', 0);
    assert.equal(limiter.check('u', true, 500).allow, false);
    assert.equal(limiter.check('u', true, 1500).allow, true);
  });

  /** A subject with no pepper is a migration event, and worth a cool-down (spec 9.4). */
  test('flags a first-time subject as a migration', () => {
    const limiter = new ReleaseLimiter();
    const decision = limiter.check('new-user', false);
    assert.equal(decision.allow, true);
    assert.equal(decision.allow === true && decision.migration, true);
  });

  test('enforces the migration cool-down when enabled', () => {
    const limiter = new ReleaseLimiter({ ...DEFAULT_RATE_LIMIT, migrationCooldownMs: 60_000 });
    const first = limiter.check('new-user', false, 0);
    assert.equal(first.allow, false);
    assert.equal(first.allow === false && first.reason, 'migration_cooldown');

    assert.equal(limiter.check('new-user', false, 61_000).allow, true);
  });

  test('rate limits are per subject', () => {
    const limiter = new ReleaseLimiter({ ...DEFAULT_RATE_LIMIT, maxPerWindow: 1 });
    limiter.record('a');
    assert.equal(limiter.check('a', true).allow, false);
    assert.equal(limiter.check('b', true).allow, true);
  });
});

describe('PepperStore', () => {
  /** Regenerating a pepper strands the user on the recovery path, or destroys their data. */
  test('never regenerates an existing pepper', async () => {
    const store = new InMemoryPepperStore();
    const first = await store.create('user-1');
    const second = await store.create('user-1');
    assert.deepEqual(first.material, second.material);
    assert.equal(first.keyId, second.keyId);
  });

  test('gives different users different peppers', async () => {
    const store = new InMemoryPepperStore();
    const a = await store.create('user-1');
    const b = await store.create('user-2');
    assert.notDeepEqual(a.material, b.material);
    assert.equal(a.material.length, 32);
  });
});

describe('handler', () => {
  async function call(headers: Record<string, string>, body: unknown) {
    const handler = createHandler({
      verifier: verifier(),
      store: new InMemoryPepperStore(),
      limiter: new ReleaseLimiter(),
      log: () => {},
    });

    const server = createServer((req, res) => {
      handler(req, res).catch(() => res.writeHead(500).end());
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;

    try {
      const res = await fetch(`http://127.0.0.1:${port}/vault/material`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(body),
      });
      return { status: res.status, headers: res.headers, body: await res.text() };
    } finally {
      server.close();
    }
  }

  test('releases material for a valid token', async () => {
    const res = await call({ authorization: `Bearer ${await token()}` }, { nonce: 'abc' });
    assert.equal(res.status, 200);

    const parsed = JSON.parse(res.body) as { material: string; keyId: string; nonce: string };
    assert.equal(Buffer.from(parsed.material, 'base64').length, 32);
    assert.ok(parsed.keyId.length > 0);
    assert.equal(parsed.nonce, 'abc', 'the nonce is echoed so the caller can bind the response');
  });

  /** A pepper must never sit in a cache, at any layer. */
  test('marks the response no-store', async () => {
    const res = await call({ authorization: `Bearer ${await token()}` }, {});
    assert.equal(res.headers.get('cache-control'), 'no-store');
  });

  test('rejects a missing or malformed authorization header', async () => {
    assert.equal((await call({}, {})).status, 401);
    assert.equal((await call({ authorization: 'Basic xyz' }, {})).status, 401);
  });

  test('rejects an invalid token without revealing why', async () => {
    const res = await call({ authorization: `Bearer ${await token({}, otherKey)}` }, {});
    assert.equal(res.status, 401);
    // Generic on purpose: a detailed reason is an oracle for probing token structure.
    assert.equal(JSON.parse(res.body).error, 'unauthorized');
  });

  test('404s anything but the material endpoint', async () => {
    const handler = createHandler({
      verifier: verifier(),
      store: new InMemoryPepperStore(),
      limiter: new ReleaseLimiter(),
      log: () => {},
    });
    const server = createServer((req, res) => {
      handler(req, res).catch(() => res.writeHead(500).end());
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    try {
      assert.equal((await fetch(`http://127.0.0.1:${port}/`)).status, 404);
    } finally {
      server.close();
    }
  });

  /** The same user must get the same bytes every time, or every vault breaks (spec 7.3). */
  test('is deterministic for the same subject', async () => {
    const shared = {
      verifier: verifier(),
      store: new InMemoryPepperStore(),
      limiter: new ReleaseLimiter(),
      log: () => {},
    };
    const handler = createHandler(shared);
    const server = createServer((req, res) => {
      handler(req, res).catch(() => res.writeHead(500).end());
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;

    try {
      const results: string[] = [];
      for (let i = 0; i < 5; i++) {
        const res = await fetch(`http://127.0.0.1:${port}/vault/material`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${await token()}`,
          },
          body: '{}',
        });
        results.push((JSON.parse(await res.text()) as { material: string }).material);
      }
      assert.equal(new Set(results).size, 1, 'the pepper must be byte-identical every call');
    } finally {
      server.close();
    }
  });
});
