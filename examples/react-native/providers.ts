import { NativeModules, Platform } from 'react-native';
import {
  VaultError,
  type KeyMaterialResult,
  type MaterialContext,
  type RecoveryFactor,
  type RecoveryReason,
} from '@sharering/react-native-envelock';

/**
 * A material provider that keeps the pepper on the device.
 *
 * ## Demo only - this is not a second factor
 *
 * A locally-stored pepper sits next to the envelope, so a rooted or jailbroken device yields
 * both and the material adds nothing the enclave key was not already contributing. The vault
 * still has the hardware key behind its OS gate, but you no longer get two independent factors.
 * Point {@link backendMaterialProvider} at something like `examples/reference-backend` for
 * that.
 *
 * ## The part it does get right
 *
 * The bytes are generated once and returned forever. That is the determinism contract, and it
 * is the part integrators break - usually by deriving material from a bearer token, which
 * rotates and orphans every vault on the next rotation.
 *
 * Note that the value is held in a module-level variable *and* persisted. Memory alone would
 * pass a determinism check inside one process and brick the vault on the next cold start,
 * which is exactly what `assertProviderDeterministic({ acrossRestarts })` exists to catch.
 */
let cachedPepper: Uint8Array | undefined;

export async function localDemoMaterialProvider(
  _ctx: MaterialContext,
): Promise<KeyMaterialResult> {
  if (!cachedPepper) {
    cachedPepper = await loadOrCreatePepper();
  }
  return {
    material: cachedPepper,
    // A fixed keyId: rotation is a deliberate act, never a side effect of a call.
    keyId: 'demo-v1',
    cacheable: true,
  };
}

/**
 * Persist the demo pepper.
 *
 * A real app has no equivalent of this at all - the pepper lives on a server. This uses a
 * deterministic value derived from a per-install id so the demo survives a restart without
 * pulling in a filesystem dependency.
 */
async function loadOrCreatePepper(): Promise<Uint8Array> {
  // `getConstants` is stable for the life of an install, which is all this needs. It is *not*
  // a secret, and a mutable device fingerprint would be a terrible source of real key material.
  const seed = `${Platform.OS}:${NativeModules.PlatformConstants?.reactNativeVersion ?? 'demo'}`;

  // FNV-1a stretched to 32 bytes. Adequate for a demo whose pepper is not a real factor;
  // never do this for production material, which must come from a CSPRNG on a server.
  const bytes = new Uint8Array(32);
  let h = 0x811c9dc5;
  for (let i = 0; i < 32; i++) {
    const ch = seed.charCodeAt(i % seed.length);
    h ^= ch + i;
    h = Math.imul(h, 0x01000193) >>> 0;
    bytes[i] = h & 0xff;
  }
  return bytes;
}

/**
 * The shape a real provider takes (spec 9.1).
 *
 * Point it at `examples/reference-backend`. It carries a bearer token to *fetch* the material
 * and never derives anything from it.
 */
export function backendMaterialProvider(
  endpoint: string,
  bearerToken: () => Promise<string>,
) {
  return async (ctx: MaterialContext): Promise<KeyMaterialResult> => {
    // A production build must refuse plain HTTP outright: the pepper is in the response.
    if (!endpoint.startsWith('https://') && !endpoint.includes('localhost') && !endpoint.includes('10.0.2.2')) {
      throw VaultError.misconfigured('refusing to fetch key material over plain HTTP');
    }

    let response: Response;
    try {
      response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${await bearerToken()}`,
        },
        // The nonce lets the backend bind its response to this request. envelock does not
        // inspect it; nothing in the key hierarchy depends on it.
        body: JSON.stringify({ nonce: toBase64(ctx.nonce) }),
      });
    } catch {
      // A transport failure is retryable, never a denial: treating it as `denied` would let a
      // backend outage march a legitimate user into lockout (spec 7.4).
      throw VaultError.unavailable('could not reach the material endpoint');
    }

    if (response.status === 401 || response.status === 403) throw VaultError.denied();
    if (!response.ok) throw VaultError.unavailable(`backend returned ${response.status}`);

    const body = (await response.json()) as { material: string; keyId: string };
    return { material: fromBase64(body.material), keyId: body.keyId };
  };
}

/**
 * Supplies the recovery factor.
 *
 * A wallet would derive this from its BIP-39 seed with `envelock-bip85`, at a hardened path,
 * and would never let the seed phrase itself reach envelock. This demo uses a fixed key so the
 * recovery path can be exercised without a wallet.
 *
 * **The recovery factor is not the host app's PIN** (spec 0). envelock never compares it
 * against a stored value; it is KDF input and nothing else.
 */
export const demoRecoveryKey = new Uint8Array(
  Array.from({ length: 32 }, (_, i) => (i * 7 + 3) % 256),
);

export let lastRecoveryReason: RecoveryReason | undefined;

export async function demoRecoveryProvider(
  reason: RecoveryReason,
): Promise<RecoveryFactor> {
  lastRecoveryReason = reason;
  // A wallet would call `deriveRecoveryKey(seed, 0)` here instead.
  return { kind: 'highEntropy', bytes: demoRecoveryKey };
}

/** UTF-8 encode, without depending on a `TextEncoder` global. */
export function utf8Encode(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}

/** UTF-8 decode, without depending on a `TextDecoder` global. */
export function utf8Decode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; ) {
    const b = bytes[i]!;
    if (b < 0x80) {
      out += String.fromCharCode(b);
      i += 1;
    } else if (b < 0xe0) {
      out += String.fromCharCode(((b & 31) << 6) | (bytes[i + 1]! & 63));
      i += 2;
    } else {
      out += String.fromCharCode(
        ((b & 15) << 12) | ((bytes[i + 1]! & 63) << 6) | (bytes[i + 2]! & 63),
      );
      i += 3;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// base64, for talking to a JSON backend
//
// Note where this lives: in the *app*, for its own HTTP payloads. envelock itself no longer
// encodes anything - record bytes and provider material reach native memory through JSI, so
// nothing sensitive is ever a JavaScript string.
// ---------------------------------------------------------------------------------------

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1];
    const c = bytes[i + 2];
    const n = (a << 16) | ((b ?? 0) << 8) | (c ?? 0);
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]!;
    out += b === undefined ? '=' : B64[(n >> 6) & 63]!;
    out += c === undefined ? '=' : B64[n & 63]!;
  }
  return out;
}

function fromBase64(text: string): Uint8Array {
  const clean = text.replace(/[^A-Za-z0-9+/]/g, '');
  const out = new Uint8Array((clean.length * 3) >> 2);
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const n =
      (B64.indexOf(clean[i]!) << 18) |
      (B64.indexOf(clean[i + 1]!) << 12) |
      ((clean[i + 2] ? B64.indexOf(clean[i + 2]!) : 0) << 6) |
      (clean[i + 3] ? B64.indexOf(clean[i + 3]!) : 0);
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}
