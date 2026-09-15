/// envelock for Flutter.
///
/// ## The three secrets - read this before anything else (spec 0)
///
/// | Term | What it is | Who sees it |
/// |---|---|---|
/// | **App login credential** | Whatever your app logs its user in with, usually verified server-side | Your app only. **Never envelock.** |
/// | **Provider material** | >=32 stable bytes you supply via [VaultOptions.getKeyMaterial] | You and your backend |
/// | **Recovery factor** | Opens the vault when the enclave key is gone | envelock only |
///
/// The recovery factor is **not** your login credential. It is never compared against a stored value;
/// it is KDF input and nothing else. Integrators assume otherwise unless told plainly.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/foundation.dart'
    show
        ErrorDescription,
        FlutterError,
        FlutterErrorDetails,
        TargetPlatform,
        defaultTargetPlatform,
        kIsWeb;
import 'package:flutter/widgets.dart';

import 'src/messages.g.dart';

export 'src/messages.g.dart'
    show WireHardwareBacking, WireMaterialReason, WireRecoveryKind, WireRecoveryReason;

// ---------------------------------------------------------------------------------------
// Public value types
// ---------------------------------------------------------------------------------------

typedef MaterialReason = WireMaterialReason;
typedef RecoveryReason = WireRecoveryReason;
typedef HardwareBacking = WireHardwareBacking;
typedef RecoveryKind = WireRecoveryKind;

extension HardwareBackingX on HardwareBacking {
  /// Whether the spec 2.3 security floor actually holds on this device.
  bool get isHardwareBacked => this != WireHardwareBacking.software;
}

class MaterialContext {
  const MaterialContext({
    required this.reason,
    required this.nonce,
    required this.deadlineMs,
  });

  final MaterialReason reason;

  /// 32 fresh bytes for challenge-response with your own backend. envelock never inspects any
  /// response; nothing in the key hierarchy depends on it.
  final Uint8List nonce;

  /// envelock enforces this itself. A hung callback becomes [VaultErrorCode.unavailable].
  final int deadlineMs;
}

class KeyMaterial {
  const KeyMaterial({
    required this.material,
    required this.keyId,
    this.cacheable = true,
    this.cacheTtlMs = 30 * 24 * 60 * 60 * 1000,
  });

  /// At least 32 bytes, and **byte-identical on every call** for a given [keyId].
  ///
  /// Valid sources: a server-held per-user pepper, a value stored in envelock at enrollment,
  /// WebAuthn PRF output for a fixed salt.
  ///
  /// Invalid, and they will permanently brick user data: bearer/access/refresh tokens (they
  /// rotate); anything containing a timestamp, request id or nonce; device fingerprints from
  /// mutable OS properties; anything derived from a login credential (spec 7.3).
  final Uint8List material;

  /// Changes only on deliberate rotation, which triggers an automatic rewrap (spec 8.3).
  final String keyId;
  final bool cacheable;
  final int cacheTtlMs;
}

/// The recovery factor.
sealed class RecoveryFactor {
  const RecoveryFactor();

  /// 32 uniform bytes - typically a BIP-85 child key derived from the wallet's BIP-39 seed.
  /// 128 bits is not guessable, so no attempt limiting applies.
  factory RecoveryFactor.highEntropy(Uint8List bytes) = HighEntropyFactor;

  /// A user-chosen passphrase. Argon2id stretches it and the spec 10 backoff ladder engages,
  /// up to destroying the vault after repeated failures.
  ///
  /// **Not** the host app's PIN (spec 0).
  factory RecoveryFactor.passphrase(String value) = PassphraseFactor;
}

class HighEntropyFactor extends RecoveryFactor {
  const HighEntropyFactor(this.bytes);
  final Uint8List bytes;
}

class PassphraseFactor extends RecoveryFactor {
  const PassphraseFactor(this.value);
  final String value;
}

sealed class VaultState {
  const VaultState();
}

class NotEnrolled extends VaultState {
  const NotEnrolled();
}

class Locked extends VaultState {
  const Locked();
}

class Unlocked extends VaultState {
  const Unlocked();
}

/// Recovery attempts are being throttled (spec 10). Passphrase vaults only.
class LockedOut extends VaultState {
  const LockedOut(this.untilMs);
  final int untilMs;
}

/// The envelope exists but the enclave key does not - a restored backup on a new device.
class NeedsRecovery extends VaultState {
  const NeedsRecovery();
}

class SecurityInfo {
  const SecurityInfo({
    required this.hardwareBacking,
    required this.providerId,
    required this.keyId,
    required this.recoveryKind,
    required this.enrolledAt,
    required this.failedAttempts,
    required this.lockedUntil,
    this.materialCachedUntil,
  });

  /// Reported truthfully. `software` means the spec 2.3 security floor does not hold.
  final HardwareBacking hardwareBacking;
  final String providerId;
  final String keyId;
  final RecoveryKind recoveryKind;
  final int enrolledAt;
  final int failedAttempts;
  final int lockedUntil;
  final int? materialCachedUntil;
}

class SecurityEvent {
  const SecurityEvent(this.type, this.details);
  final String type;
  final Map<String, Object?> details;

  @override
  String toString() => 'SecurityEvent($type, $details)';
}

/// How your callback rejects decides whether a legitimate user is locked out (spec 7.4).
enum VaultErrorCode {
  /// User dismissed a prompt. Normal; **not** counted. Render a calm state.
  cancelled,

  /// Offline or backend down. Retryable; **not** counted.
  unavailable,

  /// Verification genuinely failed. The **only** code that counts toward lockout.
  denied,

  /// Your bug. Surfaced loudly; **not** counted.
  misconfigured,

  /// Your callback returned different bytes than at enrollment.
  providerMaterialMismatch,

  /// Expected; drive [Vault.unlockWithRecovery] to rewrap.
  providerKeyRotated,

  /// The material failed the enrollment sanity checks.
  materialRejected,

  /// Stored data is corrupt or was tampered with.
  corruptData,

  /// Anything else. Treated as retryable.
  unexpected,

  /// No enclave on this platform - web or desktop (spec 6.4).
  ///
  /// Never returned by a callback; raised by [Vault.open]. envelock's security floor is a
  /// hardware-backed, biometric-gated key, and spec 6.4 is explicit that a software key
  /// reported as the same posture is worse than refusing outright.
  platformUnsupported,
}

class VaultException implements Exception {
  const VaultException(this.code, [this.message]);

  final VaultErrorCode code;
  final String? message;

  /// User dismissed a prompt. Never counted toward lockout.
  const VaultException.cancelled([String? message])
      : this(VaultErrorCode.cancelled, message);

  /// Transient failure. Retryable; never counted.
  const VaultException.unavailable([String? message])
      : this(VaultErrorCode.unavailable, message);

  /// Verification genuinely failed. The only code that counts toward lockout.
  const VaultException.denied([String? message])
      : this(VaultErrorCode.denied, message);

  /// An integrator bug worth surfacing loudly. Never counted.
  const VaultException.misconfigured([String? message])
      : this(VaultErrorCode.misconfigured, message);

  @override
  String toString() => 'VaultException(${code.name}${message == null ? '' : ': $message'})';
}

class VaultOptions {
  const VaultOptions({
    required this.providerId,
    required this.getKeyMaterial,
    required this.getRecoveryFactor,
    this.onSecurityEvent,
    this.autoLockMs = 300000,
    this.callbackDeadlineMs = 30000,
    this.destroyAfterAttempts = 11,
    this.directory,
  });

  /// Namespaced into derivation. **Changing it invalidates every existing vault.**
  final String providerId;

  /// Supplies the provider material - your half of `KEK_primary`.
  ///
  /// There is no token parameter here and no endpoint option anywhere in envelock. If fetching
  /// material needs a bearer token, obtain and use it inside this function. That keeps "the
  /// token is a credential for *fetching* material, never the material itself" structural
  /// rather than a line in the docs (spec 7.3).
  ///
  /// **It must be deterministic.** Verify that in CI with `assertProviderDeterministic`.
  final Future<KeyMaterial> Function(MaterialContext ctx) getKeyMaterial;

  /// Supplies the recovery factor. envelock ships no UI, so this is required.
  final Future<RecoveryFactor> Function(RecoveryReason reason) getRecoveryFactor;

  final void Function(SecurityEvent event)? onSecurityEvent;

  /// Inactivity timeout before the DEK is zeroized. `0` disables auto-lock.
  final int autoLockMs;
  final int callbackDeadlineMs;

  /// Failed recovery attempts before destruction. Null disables it. Passphrase vaults only -
  /// a high-entropy factor carries no counter.
  final int? destroyAfterAttempts;

  final String? directory;
}

// ---------------------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------------------

/// The vault.
///
/// ## Lifecycle
///
/// [open] installs a [WidgetsBindingObserver] that locks the vault on
/// `AppLifecycleState.paused`. Zeroization happens inside the Rust core - dropping a Dart
/// reference gives no guarantee the key bytes ever leave memory, because Dart offers no
/// control over the garbage collector (spec 11.3).
class Vault {
  Vault._(this._api, this._vaultId, this.directory);

  final EnvelockHostApi _api;

  /// Names this vault on every call. The plugin holds a map, so several vaults coexist.
  final String _vaultId;

  /// The resolved storage directory.
  final String directory;

  _LifecycleObserver? _observer;
  bool _disposed = false;

  static final Map<String, VaultOptions> _open = {};
  static bool _routerInstalled = false;


  static Future<Vault> open(VaultOptions options) async {
    // First, so web and desktop get a named reason instead of an opaque channel error.
    _assertPlatformSupported();

    WidgetsFlutterBinding.ensureInitialized();

    final api = EnvelockHostApi();
    if (!_routerInstalled) {
      EnvelockFlutterApi.setUp(_CallbackRouter(api));
      _routerInstalled = true;
    }

    final handle = await _guard(
      () => api.create(
        WireVaultConfig(
          providerId: options.providerId,
          directory: options.directory,
          autoLockMs: options.autoLockMs,
          callbackDeadlineMs: options.callbackDeadlineMs,
          destroyAfterAttempts: options.destroyAfterAttempts,
        ),
      ),
    );

    _open[handle.vaultId] = options;

    final vault = Vault._(api, handle.vaultId, handle.directory);
    vault._observer = _LifecycleObserver(vault);
    WidgetsBinding.instance.addObserver(vault._observer!);

    return vault;
  }

  EnvelockHostApi get _live {
    if (_disposed) {
      throw const VaultException(
        VaultErrorCode.misconfigured,
        'this vault has been disposed; open a new one rather than reusing the instance',
      );
    }
    return _api;
  }

  Future<VaultState> state() async {
    final r = await _guard(() => _live.state(_vaultId));
    return switch (r.state) {
      WireVaultState.notEnrolled => const NotEnrolled(),
      WireVaultState.locked => const Locked(),
      WireVaultState.unlocked => const Unlocked(),
      WireVaultState.needsRecovery => const NeedsRecovery(),
      WireVaultState.lockedOut => LockedOut(r.lockedUntilMs ?? 0),
    };
  }

  Future<void> enroll(RecoveryFactor factor) =>
      _guard(() => _live.enroll(_vaultId, _encodeFactor(factor)));

  /// Primary path: one OS biometric prompt, cached material, works offline (spec 8.2).
  Future<void> unlock() => _guard(() => _live.unlock(_vaultId));

  /// Recovery path. Provisions a fresh enclave key and rewraps the primary path in the same
  /// operation, so the *next* unlock is biometric-only (spec 8.4).
  Future<void> unlockWithRecovery() => _guard(() => _live.unlockWithRecovery(_vaultId));

  Future<void> changeRecoveryFactor(RecoveryFactor factor) =>
      _guard(() => _live.changeRecoveryFactor(_vaultId, _encodeFactor(factor)));

  Future<void> put(String recordId, Uint8List value) =>
      _guard(() => _live.put(_vaultId, recordId, value));

  Future<Uint8List?> get(String recordId) => _guard(() => _live.get(_vaultId, recordId));

  Future<void> delete(String recordId) => _guard(() => _live.delete(_vaultId, recordId));

  Future<List<String>> list([String prefix = '']) => _guard(() => _live.list(_vaultId, prefix));

  /// Zeroize the in-memory DEK. Called automatically when the app is paused.
  Future<void> lock() => _guard(() => _live.lock(_vaultId));

  /// Irreversible: deletes the enclave key, envelope, cache and every record.
  Future<void> destroy() => _guard(() => _live.destroyVault(_vaultId));

  Future<SecurityInfo> securityInfo() async {
    final i = await _guard(() => _live.securityInfo(_vaultId));
    return SecurityInfo(
      hardwareBacking: i.hardwareBacking,
      providerId: i.providerId,
      keyId: i.keyId,
      recoveryKind: i.recoveryKind,
      enrolledAt: i.enrolledAt,
      failedAttempts: i.failedAttempts,
      lockedUntil: i.lockedUntil,
      materialCachedUntil: i.materialCachedUntil,
    );
  }

  Future<void> dispose() async {
    if (_observer != null) {
      WidgetsBinding.instance.removeObserver(_observer!);
      _observer = null;
    }
    if (_disposed) return;
    _disposed = true;
    _open.remove(_vaultId);
    await _api.dispose(_vaultId);
  }

}

/// Map a platform error onto the documented taxonomy.
///
/// Anything unrecognised becomes [VaultErrorCode.unavailable]: retryable and uncounted.
/// Defaulting to `denied` would let a transport hiccup march a legitimate user toward
/// lockout (spec 7.4).
///
/// Top-level rather than a method on [Vault] so [Vault.open] can use it before an instance
/// exists - which is exactly when the platform turns out to be unsupported.
Future<T> _guard<T>(Future<T> Function() body) async {
  try {
    return await body();
  } on VaultException {
    rethrow;
  } catch (e) {
    throw VaultException(_codeFromError(e), e.toString());
  }
}

/// Fail with [VaultErrorCode.platformUnsupported] anywhere there is no enclave (spec 6.4).
///
/// Checked against the platform rather than inferred from a channel failure. Pigeon does not
/// raise `MissingPluginException`: an unhandled channel replies null and the generated code
/// turns that into `PlatformException('channel-error')`, which is also what a genuine
/// transport fault on iOS or Android looks like. Those two must not collapse into one code -
/// one means "envelock cannot run here", the other means "your build is broken".
void _assertPlatformSupported() {
  final supported = !kIsWeb &&
      (defaultTargetPlatform == TargetPlatform.iOS ||
          defaultTargetPlatform == TargetPlatform.android);
  if (supported) return;

  throw const VaultException(
    VaultErrorCode.platformUnsupported,
    'envelock requires iOS or Android: it is backed by the Secure Enclave or the Android '
    'Keystore, and this platform has neither. Spec 6.4 refuses rather than falling back to '
    'a software key, which would report the same posture while providing none of it.',
  );
}

VaultErrorCode _codeFromError(Object e) {
  final text = e is PlatformExceptionLike ? e.code : e.toString();
  for (final code in VaultErrorCode.values) {
    if (text.contains(code.name)) return code;
  }
  return VaultErrorCode.unavailable;
}

/// Structural match for `PlatformException` without importing services.dart into the type.
abstract class PlatformExceptionLike {
  String get code;
}

WireRecoveryFactor _encodeFactor(RecoveryFactor factor) => switch (factor) {
      HighEntropyFactor(:final bytes) =>
        WireRecoveryFactor(highEntropyBytes: bytes),
      PassphraseFactor(:final value) => WireRecoveryFactor(passphrase: value),
    };

class _LifecycleObserver with WidgetsBindingObserver {
  _LifecycleObserver(this._vault);
  final Vault _vault;

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Spec 11.3: zeroize on background. `paused` is the last callback guaranteed before the
    // app may be killed, so it is the only safe place to do this.
    //
    // **Not `inactive`.** The OS biometric sheet, the app switcher and Control Centre all
    // produce `inactive` while the app is still very much in use - and the biometric sheet is
    // raised by `unlock()` itself, so locking there zeroizes the DEK that the user just
    // authenticated for, and the next read fails with "vault is locked".
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
      case AppLifecycleState.detached:
        unawaited(_vault.lock().catchError((_) {}));
      case AppLifecycleState.resumed:
      case AppLifecycleState.inactive:
        break;
    }
  }
}

/// Serves provider callbacks from native code.
///
/// Native is blocking a background thread on each of these, so every request **must** be
/// answered exactly once - including when the user's callback throws something that is not a
/// [VaultException].
class _CallbackRouter implements EnvelockFlutterApi {
  _CallbackRouter(this._api);

  final EnvelockHostApi _api;

  VaultOptions? _optionsFor(String vaultId) => Vault._open[vaultId];

  @override
  void onKeyMaterialRequested(WireMaterialContext ctx) {
    final options = _optionsFor(ctx.vaultId);
    if (options == null) return _abandon(ctx.vaultId, ctx.requestId);

    unawaited(_serve(ctx.requestId, () async {
      final result = await options.getKeyMaterial(
        MaterialContext(
          reason: ctx.reason,
          nonce: ctx.nonce,
          deadlineMs: ctx.deadlineMs,
        ),
      );
      // Packed as bytes plus a text field so the native side can rebuild the record without a
      // second round trip: keyId and the cache policy ride along in `payloadText`.
      return (
        result.material,
        '${result.keyId}\u0000${result.cacheable}\u0000${result.cacheTtlMs}',
      );
    }));
  }

  @override
  void onRecoveryFactorRequested(
    String vaultId,
    String requestId,
    WireRecoveryReason reason,
  ) {
    final options = _optionsFor(vaultId);
    if (options == null) return _abandon(vaultId, requestId);

    unawaited(_serve(requestId, () async {
      final factor = await options.getRecoveryFactor(reason);
      return switch (factor) {
        HighEntropyFactor(:final bytes) => (bytes, 'highEntropy'),
        PassphraseFactor(:final value) => (null, 'passphrase\u0000$value'),
      };
    }));
  }

  @override
  void onSecurityEvent(String vaultId, WireSecurityEvent event) {
    _optionsFor(vaultId)?.onSecurityEvent?.call(SecurityEvent(event.type, {
      'hardware': event.hardware,
      'usedCache': event.usedCache,
      'counted': event.counted,
      'from': event.from,
      'to': event.to,
      'reason': event.reason,
      'untilMs': event.untilMs,
    }..removeWhere((_, v) => v == null)));
  }

  void _abandon(String vaultId, String requestId) {
    FlutterError.reportError(FlutterErrorDetails(
      exception: StateError(
        'envelock: a provider callback arrived for vault "$vaultId", which is not open. '
        'Open vaults: ${Vault._open.keys.toList()}. Answering `unavailable`.',
      ),
      library: 'envelock',
      context: ErrorDescription('routing a provider callback'),
    ));
    unawaited(_api.resolveCallback(
      requestId,
      null,
      null,
      WireErrorCode.unavailable,
      'the vault was disposed while its provider callback was in flight',
    ));
  }

  Future<void> _serve(
    String requestId,
    Future<(Uint8List?, String?)> Function() run,
  ) async {
    try {
      final (bytes, text) = await run();
      await _api.resolveCallback(requestId, bytes, text, null, null);
    } on VaultException catch (e) {
      await _api.resolveCallback(
        requestId,
        null,
        null,
        _toWireCode(e.code),
        e.message ?? e.code.name,
      );
    } catch (e, stack) {
      FlutterError.reportError(FlutterErrorDetails(
        exception: e,
        stack: stack,
        library: 'envelock',
        context: ErrorDescription(
          'serving a provider callback; envelock reports this as `unavailable`',
        ),
      ));
      await _api.resolveCallback(
        requestId,
        null,
        null,
        WireErrorCode.unavailable,
        e.toString(),
      );
    }
  }
}

WireErrorCode _toWireCode(VaultErrorCode code) => switch (code) {
      VaultErrorCode.cancelled => WireErrorCode.cancelled,
      VaultErrorCode.unavailable => WireErrorCode.unavailable,
      VaultErrorCode.denied => WireErrorCode.denied,
      VaultErrorCode.misconfigured => WireErrorCode.misconfigured,
      VaultErrorCode.providerMaterialMismatch => WireErrorCode.providerMaterialMismatch,
      VaultErrorCode.providerKeyRotated => WireErrorCode.providerKeyRotated,
      VaultErrorCode.materialRejected => WireErrorCode.materialRejected,
      VaultErrorCode.corruptData => WireErrorCode.corruptData,
      VaultErrorCode.unexpected => WireErrorCode.unexpected,
      // Unreachable in practice: a callback has no reason to raise it, and the vault could not
      // have been opened on an unsupported platform to invoke one. Mapped to the retryable,
      // uncounted code rather than left to throw.
      VaultErrorCode.platformUnsupported => WireErrorCode.unexpected,
    };
