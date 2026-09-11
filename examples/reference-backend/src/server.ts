/**
 * The reference material endpoint (spec 9).
 *
 * ```
 * app -> this server   { bearerToken, nonce }
 * server: verify the token against the host's JWKS -> sub
 * server -> app        { material: pepper[sub], keyId }
 * ```
 *
 * envelock ships no HTTP client and makes no assumptions about endpoint shape. This exists so
 * an integrator can copy a working, correct backend rather than invent one - and so the
 * security-critical details in spec 9.2 have somewhere concrete to live.
 *
 * Run with `pnpm start`. Configuration comes from the environment; see `readConfig`.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import {
  DEFAULT_RATE_LIMIT,
  InMemoryPepperStore,
  ReleaseLimiter,
  type PepperStore,
  type RateLimitPolicy,
} from './pepper.ts';
import { SUB_STABILITY_WARNING, TokenVerifier, VerificationError } from './verify.ts';

export interface ServerDeps {
  verifier: Pick<TokenVerifier, 'verify'>;
  store: PepperStore;
  limiter: ReleaseLimiter;
  log?: (event: Record<string, unknown>) => void;
}

/** Requests larger than this are rejected unread. */
const MAX_BODY_BYTES = 8 * 1024;

export function createHandler(deps: ServerDeps) {
  const log = deps.log ?? ((e) => console.log(JSON.stringify(e)));

  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST' || req.url !== '/vault/material') {
      return send(res, 404, { error: 'not_found' });
    }

    const auth = req.headers.authorization;
    if (typeof auth !== 'string' || !auth.startsWith('Bearer ')) {
      return send(res, 401, { error: 'unauthorized' });
    }

    let body: { nonce?: unknown };
    try {
      body = JSON.parse(await readBody(req)) as { nonce?: unknown };
    } catch {
      return send(res, 400, { error: 'bad_request' });
    }

    // The nonce is the caller's challenge, echoed back so it can bind the response to its own
    // request. envelock does not inspect it; nothing in the key hierarchy depends on it.
    const nonce = typeof body.nonce === 'string' ? body.nonce : undefined;

    let sub: string;
    try {
      ({ sub } = await deps.verifier.verify(auth.slice('Bearer '.length)));
    } catch (e) {
      // Deliberately generic. Telling the caller *why* verification failed turns this endpoint
      // into an oracle for probing token structure.
      log({ event: 'verification_failed', reason: (e as VerificationError).reason });
      return send(res, 401, { error: 'unauthorized' });
    }

    const existing = await deps.store.get(sub);
    const decision = deps.limiter.check(sub, existing !== undefined);

    if (!decision.allow) {
      log({ event: 'release_blocked', sub, reason: decision.reason });
      res.setHeader('Retry-After', Math.ceil(decision.retryAfterMs / 1000).toString());
      return send(res, 429, { error: decision.reason });
    }

    if (decision.migration) {
      // A subject with no enrollment history is asking for material for the first time. On a
      // real deployment this is worth alerting on: it is what an account takeover looks like
      // from here (spec 9.4).
      log({ event: 'migration', sub, note: 'first material release for this subject' });
    }

    const record = existing ?? (await deps.store.create(sub));
    deps.limiter.record(sub);
    log({ event: 'released', sub, keyId: record.keyId });

    return send(res, 200, {
      material: record.material.toString('base64'),
      keyId: record.keyId,
      ...(nonce === undefined ? {} : { nonce }),
    });
  };
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
    // The response carries a pepper. It must not be cached anywhere, by anything.
    'cache-control': 'no-store',
  });
  res.end(payload);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------

function readConfig() {
  const required = (name: string): string => {
    const value = process.env[name];
    if (!value) throw new Error(`${name} is required`);
    return value;
  };

  const rateLimit: RateLimitPolicy = {
    ...DEFAULT_RATE_LIMIT,
    // Off by default so the quickstart is not confusing. Turn it on before production:
    // it is the control that makes a stolen token expensive to use (spec 9.4).
    migrationCooldownMs: Number(process.env.MIGRATION_COOLDOWN_MS ?? 0),
  };

  return {
    port: Number(process.env.PORT ?? 8787),
    verifier: new TokenVerifier({
      jwksUri: new URL(required('HOST_JWKS_URI')),
      // Pinned, never read from the token header.
      algorithms: (process.env.HOST_ALGORITHMS ?? 'RS256').split(','),
      issuers: required('HOST_ISSUER').split(','),
      audiences: required('HOST_AUDIENCE').split(','),
    }),
    rateLimit,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const config = readConfig();
  const handler = createHandler({
    verifier: config.verifier,
    store: new InMemoryPepperStore(),
    limiter: new ReleaseLimiter(config.rateLimit),
  });

  createServer((req, res) => {
    handler(req, res).catch((e) => {
      console.error(e);
      send(res, 500, { error: 'internal' });
    });
  }).listen(config.port, () => {
    console.error(`envelock reference backend listening on :${config.port}`);
    console.error('');
    console.error('BEFORE PRODUCTION');
    console.error('  - Peppers here are in memory and vanish on restart, taking every');
    console.error('    user vault with them. Move them to a KMS-encrypted store.');
    console.error(`  - MIGRATION_COOLDOWN_MS is ${config.rateLimit.migrationCooldownMs}ms.`);
    console.error('');
    console.error(SUB_STABILITY_WARNING);
  });
}
