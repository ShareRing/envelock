import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:envelock/envelock.dart';
import 'package:path_provider/path_provider.dart';

/// A material provider that keeps the pepper on the device.
///
/// ## Demo only - this is not a second factor
///
/// A locally-stored pepper sits next to the envelope, so a rooted or jailbroken device yields
/// both and the material adds nothing the enclave key was not already contributing. The vault
/// still has the hardware key behind its OS gate, but you no longer get two independent factors.
/// Point [BackendMaterialProvider] at something like `examples/reference-backend` for that.
///
/// What it does get right: the bytes are written once and read back forever. That is the
/// determinism contract, and the part integrators break.
class LocalDemoMaterialProvider {
  Uint8List? _cached;

  Future<KeyMaterial> call(MaterialContext ctx) async {
    // Cached in memory *and* on disk. Memory alone would pass a determinism check inside one
    // process and brick the vault on the next cold start - the exact bug
    // `assertProviderDeterministic(acrossRestarts:)` exists to catch.
    final cached = _cached;
    if (cached != null) {
      return KeyMaterial(material: cached, keyId: 'demo-v1');
    }

    final dir = await getApplicationSupportDirectory();
    final file = File('${dir.path}/demo-pepper.bin');

    Uint8List material;
    if (file.existsSync()) {
      material = Uint8List.fromList(await file.readAsBytes());
    } else {
      final random = Random.secure();
      material = Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));
      await file.writeAsBytes(material, flush: true);
    }

    _cached = material;
    // A fixed keyId: rotation is a deliberate act, never a side effect of a call.
    return KeyMaterial(material: material, keyId: 'demo-v1');
  }
}

/// The shape a real provider takes (spec 9.1).
///
/// Point it at `examples/reference-backend`. It carries a bearer token to *fetch* the material
/// and never derives anything from it - tokens rotate, and material derived from a rotating
/// value orphans every vault on the next rotation.
class BackendMaterialProvider {
  BackendMaterialProvider({required this.endpoint, required this.bearerToken});

  final Uri endpoint;
  final Future<String> Function() bearerToken;

  Future<KeyMaterial> call(MaterialContext ctx) async {
    // A production build must refuse plain HTTP outright: the pepper is in the response.
    if (endpoint.scheme != 'https' && endpoint.host != '10.0.2.2' && endpoint.host != 'localhost') {
      throw const VaultException.misconfigured(
        'refusing to fetch key material over plain HTTP',
      );
    }

    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      final request = await client.postUrl(endpoint);
      request.headers.set('content-type', 'application/json');
      request.headers.set('authorization', 'Bearer ${await bearerToken()}');
      // The nonce lets the backend bind its response to this request.
      request.write(jsonEncode({'nonce': base64Encode(ctx.nonce)}));

      final response = await request.close();

      // 401 is a real denial and counts toward lockout. Everything else is transient and must
      // not, or a backend outage marches a legitimate user into lockout (spec 7.4).
      if (response.statusCode == 401 || response.statusCode == 403) {
        throw const VaultException.denied();
      }
      if (response.statusCode != 200) {
        throw const VaultException.unavailable();
      }

      final body = jsonDecode(await response.transform(utf8.decoder).join())
          as Map<String, Object?>;

      return KeyMaterial(
        material: base64Decode(body['material']! as String),
        keyId: body['keyId']! as String,
      );
    } on VaultException {
      rethrow;
    } catch (_) {
      // Any transport failure is retryable, never a denial.
      throw const VaultException.unavailable();
    } finally {
      client.close(force: true);
    }
  }
}

/// Supplies the recovery factor.
///
/// A wallet would derive this from its BIP-39 seed with `envelock-bip85`, at a hardened path,
/// and would never let the seed phrase itself reach envelock. This demo uses a fixed key so
/// the recovery path can be exercised without a wallet.
///
/// **The recovery factor is not the host app's PIN** (spec 0). envelock never compares it
/// against a stored value; it is KDF input and nothing else.
class DemoRecoveryProvider {
  RecoveryReason? lastReason;

  /// A wallet would call `derive_recovery_key(seed, 0)` here instead.
  static final demoKey =
      Uint8List.fromList(List.generate(32, (i) => (i * 7 + 3) % 256));

  Future<RecoveryFactor> call(RecoveryReason reason) async {
    lastReason = reason;
    return RecoveryFactor.highEntropy(demoKey);
  }
}
