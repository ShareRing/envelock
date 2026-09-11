/**
 * Host token verification (spec 9.2).
 *
 * We do not issue the bearer token and have no server-to-server relationship with the host
 * app. What we *can* do is verify the token against the host's published JWKS, which yields an
 * authenticated `sub`: a stable user identifier the client cannot forge. That is all pepper
 * release requires, and it is what preserves threat T3: an attacker who patches the client
 * still cannot obtain material, because the signature is not something the client can produce.
 *
 * Every rule below is load-bearing. Skipping one turns this file into decoration.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

export interface VerifierConfig {
  /** The host's JWKS endpoint. */
  jwksUri: URL;

  /**
   * Accepted signing algorithms - an allowlist, never read from the token header.
   *
   * Reading `alg` from the header to choose the verification method is the classic
   * `alg: none` and RS256->HS256 confusion attack: an attacker re-signs the token with the
   * public key as an HMAC secret and the server happily accepts it.
   */
  algorithms: string[];

  /** Accepted issuers. Never trust `kid` to select a key from an unverified issuer. */
  issuers: string[];

  /**
   * Accepted audiences.
   *
   * If the audience is the host app rather than your service, you are accepting a token minted
   * for someone else - a confused-deputy pattern. It is common in miniapp platforms and
   * usually accepted, but record it in SECURITY.md rather than letting a reviewer find it.
   */
  audiences: string[];

  /** Clock skew tolerance in seconds. Spec 9.2 says +/-60 and no more. */
  clockToleranceSec?: number;

  /** JWKS cache lifetime. */
  jwksCacheMaxAgeMs?: number;

  /**
   * Minimum interval between JWKS refetches triggered by an unknown `kid`.
   *
   * Without this, an attacker sends tokens with garbage `kid` values and each one forces an
   * outbound fetch - turning your service into a traffic amplifier aimed at the host's JWKS
   * endpoint, and taking your own availability down with it.
   */
  jwksCooldownMs?: number;
}

export interface VerifiedSubject {
  /** The authenticated user id. See the stability caveat in {@link SUB_STABILITY_WARNING}. */
  sub: string;
  /**
   * Seconds since epoch of the user's last authentication, if the host publishes it.
   *
   * Its presence materially improves threat T5 (a stolen token used from another device),
   * because it lets you require a *fresh* authentication before releasing material. Check the
   * actual claim set before assuming it is absent - many host platforms include it.
   */
  authTime?: number;
  /** Authentication context class, if published. */
  acr?: string;
  /** Authentication methods, if published. */
  amr?: string[];
  raw: JWTPayload;
}

export const SUB_STABILITY_WARNING = `
Confirm with the host app that 'sub' is stable across logins before going to production.
Some platforms issue pairwise or rotating subject identifiers - per session, or per miniapp
installation. If 'sub' changes across logins you cannot key the pepper on it: users would lose
access to their own data on their next sign-in. This is the only host-side dependency left in
the design (spec 9.2).
`.trim();

export class VerificationError extends Error {
  readonly reason: string;

  // Written out rather than as a TS parameter property: Node's `--experimental-strip-types`
  // runs in strip-only mode and cannot desugar those.
  constructor(reason: string, message?: string) {
    super(message ?? reason);
    this.name = 'VerificationError';
    this.reason = reason;
  }
}

export class TokenVerifier {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  private readonly config: Required<VerifierConfig>;

  constructor(config: VerifierConfig) {
    if (config.algorithms.length === 0) {
      throw new Error('algorithms must be a non-empty allowlist');
    }
    if (config.algorithms.includes('none')) {
      throw new Error("'none' is not a signing algorithm");
    }
    // An HMAC algorithm here means the verification key is a shared secret, but JWKS publishes
    // *public* keys - so accepting one is the RS256->HS256 confusion attack by configuration.
    const hmac = config.algorithms.filter((a) => a.startsWith('HS'));
    if (hmac.length > 0) {
      throw new Error(`HMAC algorithms cannot be verified against a JWKS: ${hmac.join(', ')}`);
    }
    if (config.issuers.length === 0) throw new Error('issuers must be a non-empty allowlist');
    if (config.audiences.length === 0) throw new Error('audiences must be a non-empty allowlist');

    this.config = {
      clockToleranceSec: 60,
      jwksCacheMaxAgeMs: 60 * 60 * 1000,
      jwksCooldownMs: 30 * 1000,
      ...config,
    };

    this.jwks = createRemoteJWKSet(this.config.jwksUri, {
      cacheMaxAge: this.config.jwksCacheMaxAgeMs,
      cooldownDuration: this.config.jwksCooldownMs,
    });
  }

  /**
   * Verify a bearer token and return the authenticated subject.
   *
   * Throws {@link VerificationError} for anything that fails. The caller must not distinguish
   * *why* in its HTTP response beyond a generic 401 - a detailed reason is an oracle.
   */
  async verify(token: string): Promise<VerifiedSubject> {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, this.jwks, {
        // Algorithm, issuer and audience are all pinned to allowlists, never taken from the
        // token. `jose` refuses `alg: none` outright, but pinning makes the intent explicit.
        algorithms: this.config.algorithms,
        issuer: this.config.issuers,
        audience: this.config.audiences,
        clockTolerance: this.config.clockToleranceSec,
      }));
    } catch (e) {
      throw new VerificationError('invalid_token', (e as Error).message);
    }

    if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
      throw new VerificationError('missing_sub', 'the token carries no subject');
    }

    const result: VerifiedSubject = { sub: payload.sub, raw: payload };
    if (typeof payload.auth_time === 'number') result.authTime = payload.auth_time;
    if (typeof payload.acr === 'string') result.acr = payload.acr;
    if (Array.isArray(payload.amr)) result.amr = payload.amr.filter((x) => typeof x === 'string');
    return result;
  }
}

/**
 * Require that the user authenticated recently (spec 2.4).
 *
 * Only usable when the host publishes `auth_time`. Where it is absent, threat T5 stays weaker
 * than it would otherwise be and the compensating controls are the material cache, aggressive
 * per-subject rate limiting, and treating an unknown device as a migration event.
 */
export function requireFreshAuth(
  subject: VerifiedSubject,
  maxAgeSec: number,
  nowSec = Math.floor(Date.now() / 1000),
): void {
  if (subject.authTime === undefined) {
    throw new VerificationError(
      'freshness_unavailable',
      'the host token carries no auth_time, so freshness cannot be established',
    );
  }
  if (nowSec - subject.authTime > maxAgeSec) {
    throw new VerificationError('stale_auth', 'the user has not authenticated recently enough');
  }
}
