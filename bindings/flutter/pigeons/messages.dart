import 'package:pigeon/pigeon.dart';

// Pigeon interface definition for envelock.
//
// Regenerate with:
//   dart run pigeon --input pigeons/messages.dart
//
// Pigeon generates typed channel code for Dart, Swift and Kotlin from this one file, which is
// why none of it is written by hand. Editing the generated files directly is how a binding
// starts silently disagreeing with the platform it talks to.
@ConfigurePigeon(
  PigeonOptions(
    dartOut: 'lib/src/messages.g.dart',
    dartOptions: DartOptions(),
    swiftOut: 'ios/Classes/Messages.g.swift',
    swiftOptions: SwiftOptions(),
    kotlinOut:
        'android/src/main/kotlin/network/sharering/envelock/flutter/Messages.g.kt',
    kotlinOptions: KotlinOptions(package: 'network.sharering.envelock.flutter'),
    dartPackageName: 'envelock',
  ),
)
enum WireMaterialReason { enroll, unlock, rotate }

enum WireRecoveryReason { migrate, fallback, change }

enum WireHardwareBacking { secureEnclave, strongBox, tee, software }

enum WireRecoveryKind { highEntropy, passphrase }

enum WireVaultState { notEnrolled, locked, unlocked, lockedOut, needsRecovery }

/// How a provider rejected (spec 7.4).
///
/// Only [denied] counts toward lockout. Anything unrecognised is treated as [unavailable]:
/// retryable, because a flaky network must never march a legitimate user toward lockout.
enum WireErrorCode {
  cancelled,
  unavailable,
  denied,
  misconfigured,
  providerMaterialMismatch,
  providerKeyRotated,
  materialRejected,
  corruptData,
  unexpected,
}

class WireVaultConfig {
  WireVaultConfig({
    required this.providerId,
    this.directory,
    required this.autoLockMs,
    required this.callbackDeadlineMs,
    this.destroyAfterAttempts,
  });

  /// Namespaced into derivation. Changing it invalidates every existing vault.
  String providerId;

  /// App-private storage. Null lets the platform choose.
  String? directory;

  /// Inactivity timeout before the DEK is zeroized. `0` disables auto-lock.
  int autoLockMs;
  int callbackDeadlineMs;

  /// Failed recovery attempts before destruction. Null disables it. Passphrase vaults only.
  int? destroyAfterAttempts;
}

class WireVaultHandle {
  WireVaultHandle({required this.vaultId, required this.directory});

  String vaultId;

  /// The resolved storage directory.
  String directory;
}

class WireStateResult {
  WireStateResult({required this.state, this.lockedUntilMs});

  WireVaultState state;
  int? lockedUntilMs;
}

class WireMaterialContext {
  WireMaterialContext({
    required this.vaultId,
    required this.requestId,
    required this.reason,
    required this.nonce,
    required this.deadlineMs,
  });

  String vaultId;
  String requestId;
  WireMaterialReason reason;

  /// 32 fresh bytes for challenge-response with your own backend. envelock never inspects any
  /// response; nothing in the key hierarchy depends on it.
  Uint8List nonce;
  int deadlineMs;
}

class WireKeyMaterial {
  WireKeyMaterial({
    required this.material,
    required this.keyId,
    required this.cacheable,
    required this.cacheTtlMs,
  });

  /// At least 32 bytes, byte-identical on every call for a given [keyId].
  Uint8List material;
  String keyId;
  bool cacheable;
  int cacheTtlMs;
}

/// The recovery factor. Exactly one of [highEntropyBytes] or [passphrase] is set.
///
/// Pigeon has no sum type, so this is a tagged record; the Dart API in `envelock.dart` exposes
/// a proper sealed class over it.
class WireRecoveryFactor {
  WireRecoveryFactor({this.highEntropyBytes, this.passphrase});

  /// 32 uniform bytes - a BIP-85 child key from the wallet seed, or equivalent.
  Uint8List? highEntropyBytes;

  /// A user-chosen passphrase. **Not** the host app's PIN (spec 0).
  String? passphrase;
}

class WireSecurityInfo {
  WireSecurityInfo({
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
  WireHardwareBacking hardwareBacking;
  String providerId;
  String keyId;
  WireRecoveryKind recoveryKind;
  int enrolledAt;
  int failedAttempts;
  int lockedUntil;
  int? materialCachedUntil;
}

class WireSecurityEvent {
  WireSecurityEvent({
    required this.type,
    this.hardware,
    this.usedCache,
    this.counted,
    this.from,
    this.to,
    this.reason,
    this.untilMs,
  });

  String type;
  WireHardwareBacking? hardware;
  bool? usedCache;
  bool? counted;
  String? from;
  String? to;
  String? reason;
  int? untilMs;
}

/// Dart calls native.
@HostApi()
abstract class EnvelockHostApi {
  /// Create a vault. Returns the id every later call uses to name it.
  @async
  WireVaultHandle create(WireVaultConfig config);

  @async
  void dispose(String vaultId);

  @async
  WireStateResult state(String vaultId);

  @async
  void enroll(String vaultId, WireRecoveryFactor factor);

  /// Primary path: one OS biometric prompt, cached material, works offline (spec 8.2).
  @async
  void unlock(String vaultId);

  /// Recovery path. Provisions a fresh enclave key and rewraps the primary path in the same
  /// operation, so the next unlock is biometric-only (spec 8.4).
  @async
  void unlockWithRecovery(String vaultId);

  @async
  void changeRecoveryFactor(String vaultId, WireRecoveryFactor factor);

  @async
  void put(String vaultId, String recordId, Uint8List value);

  @async
  Uint8List? get(String vaultId, String recordId);

  @async
  void delete(String vaultId, String recordId);

  @async
  List<String> list(String vaultId, String prefix);

  /// Zeroize the in-memory DEK. Call from `AppLifecycleState.paused` (spec 11.3).
  @async
  void lock(String vaultId);

  /// Irreversible: deletes the enclave key, envelope, cache and every record.
  @async
  void destroyVault(String vaultId);

  @async
  WireSecurityInfo securityInfo(String vaultId);

  /// Hand a provider callback's outcome back to native code.
  ///
  /// Native invokes the Dart provider through [EnvelockFlutterApi] and blocks a background
  /// thread waiting; this releases that wait. A null [errorCode] means success.
  void resolveCallback(
    String requestId,
    Uint8List? payload,
    String? payloadText,
    WireErrorCode? errorCode,
    String? errorMessage,
  );
}

/// Native calls Dart.
///
/// These are void and fire-and-forget on purpose: the native side is blocked on a semaphore,
/// and Dart answers by calling [EnvelockHostApi.resolveCallback] with the request id. Making
/// them return values instead would require the native side to await a Dart future from a
/// thread that is already blocked, which deadlocks.
@FlutterApi()
abstract class EnvelockFlutterApi {
  void onKeyMaterialRequested(WireMaterialContext ctx);
  void onRecoveryFactorRequested(
    String vaultId,
    String requestId,
    WireRecoveryReason reason,
  );
  void onSecurityEvent(String vaultId, WireSecurityEvent event);
}
