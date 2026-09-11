/// A stand-in for the ShareRing Vault SDK - the layer external apps actually install.
///
/// envelock is *inside* this file, not in the app above it. The app never sees `Vault`,
/// never calls `put`/`get`/`list`, and never learns that a state machine exists. It gets four
/// entry points: [initialize], [destroy], [getDocument], [getRecoveryFactor].
///
/// This lives in the example so the layering is visible end to end. In production it is a
/// separate package (`package:sharering_sdk`) and everything below is its private plumbing.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

import 'package:bip39/bip39.dart' as bip39;
import 'package:envelock/envelock.dart';

// The app handles vault errors and supplies key material, so these types cross the boundary.
// Nothing else does: `Vault` itself is not exported, deliberately.
export 'package:envelock/envelock.dart'
    show
        KeyMaterial,
        MaterialContext,
        RecoveryReason,
        SecurityEvent,
        VaultErrorCode,
        VaultException;

/// What the app hands the SDK. Everything envelock-shaped is here, and nothing else.
class SdkVaultOptions {
  const SdkVaultOptions({
    required this.providerId,
    required this.getKeyMaterial,
    required this.promptRecoveryPhrase,
    this.onSecurityEvent,
    this.autoLockMs = 300000,
  });

  /// Namespaced into every derivation. **Changing it invalidates every existing vault.**
  final String providerId;

  /// Must return byte-identical material every call.
  final Future<KeyMaterial> Function(MaterialContext ctx) getKeyMaterial;

  /// Asked for the 12 words on a device that has never held them: a restored backup, a new
  /// phone. The SDK holds the phrase for the life of a session, so this fires rarely - but
  /// there is no way around it, because the enclave key cannot travel between devices.
  final Future<String> Function(RecoveryReason reason) promptRecoveryPhrase;

  final void Function(SecurityEvent event)? onSecurityEvent;
  final int autoLockMs;
}

class SdkOptions {
  const SdkOptions({
    required this.appId,
    required this.vaultOptions,
    required this.fetchDocument,
  });

  final String appId;
  final SdkVaultOptions vaultOptions;

  /// Where a document comes from the first time. After that it is served from the vault,
  /// offline, with no network call - that is the point of the vault.
  final Future<Uint8List> Function(String documentId) fetchDocument;
}

/// What [ShareRingVaultSdk] does next, given what the vault says it is.
///
/// Pulled out as a pure function so the routing can be tested without a Secure Enclave; the
/// vault's own states never reach the app above.
enum SdkStep { ready, enroll, unlock, recover, lockedOut }

SdkStep stepFor(VaultState state) => switch (state) {
      Unlocked() => SdkStep.ready,
      NotEnrolled() => SdkStep.enroll,
      Locked() => SdkStep.unlock,
      NeedsRecovery() => SdkStep.recover,
      LockedOut() => SdkStep.lockedOut,
    };

class ShareRingVaultSdk {
  ShareRingVaultSdk._(this._options);

  final SdkOptions _options;
  late final Vault _vault;

  /// Held in memory only. Persisted inside the vault, never beside it: app storage is
  /// plaintext on a rooted device and the phrase opens everything.
  String? _phrase;

  static const _phraseRecord = 'sys:recovery-phrase';

  /// Opens the vault and enrolls if this is the first run.
  ///
  /// One call per app process. It installs a lifecycle observer that locks on background, so a
  /// second instance would fight the first.
  static Future<ShareRingVaultSdk> initialize(SdkOptions options) async {
    final sdk = ShareRingVaultSdk._(options);
    final v = options.vaultOptions;

    // Its own directory, so the SDK's vault and a vault the app opens itself never fight over
    // one envelope.
    final support = await getApplicationSupportDirectory();

    sdk._vault = await Vault.open(
      VaultOptions(
        providerId: v.providerId,
        directory: '${support.path}/sharering-sdk',
        getKeyMaterial: v.getKeyMaterial,
        // The app supplies material; the SDK owns recovery. This is why `getRecoveryFactor`
        // is absent from [SdkVaultOptions].
        getRecoveryFactor: sdk._recoveryFactor,
        onSecurityEvent: v.onSecurityEvent,
        autoLockMs: v.autoLockMs,
      ),
    );

    await sdk._ready();
    return sdk;
  }

  /// The 12 words. Show them once at setup and let the user write them down.
  ///
  /// Reading them needs an unlocked vault (they are stored in it) so this costs a biometric
  /// prompt on a locked session, which is the correct price for revealing them.
  Future<String> getRecoveryFactor() async {
    final held = _phrase;
    if (held != null) return held;

    await _ready();
    final stored = await _vault.get(_phraseRecord);
    if (stored == null) {
      throw const VaultException(
        VaultErrorCode.corruptData,
        'the vault is enrolled but holds no recovery phrase',
      );
    }
    return _phrase = utf8.decode(stored);
  }

  /// Cached in the vault after the first fetch; every later call is offline.
  Future<Map<String, Object?>> getDocument(String documentId) async {
    await _ready();

    final id = 'doc:$documentId';
    final cached = await _vault.get(id);
    if (cached != null) {
      return jsonDecode(utf8.decode(cached)) as Map<String, Object?>;
    }

    final fetched = await _options.fetchDocument(documentId);
    await _vault.put(id, fetched);
    return jsonDecode(utf8.decode(fetched)) as Map<String, Object?>;
  }

  /// Irreversible: enclave key, envelope, cache and every document. The 12 words do not bring
  /// this back - nothing does.
  Future<void> destroy() async {
    await _vault.destroy();
    await _vault.dispose();
    _phrase = null;
  }

  /// Drive the vault to `Unlocked`, whatever it currently is.
  Future<void> _ready() async {
    final state = await _vault.state();
    switch (stepFor(state)) {
      case SdkStep.ready:
        return;

      case SdkStep.enroll:
        // ponytail: a passphrase factor, so the spec 10 backoff ladder applies and 11 failed
        // attempts destroy the vault. Deriving 32 bytes from the seed with envelock-bip85 and
        // enrolling `highEntropy` instead drops the ladder entirely - do that once a wallet
        // seed is available to derive from.
        // A checksummed BIP-39 mnemonic. The Android, iOS and React Native examples draw 12
        // uniform words from the same list instead, because those platforms have no BIP-39
        // package to hand; a checksummed phrase satisfies that rule too.
        final phrase = bip39.generateMnemonic();
        await _vault.enroll(RecoveryFactor.passphrase(phrase));
        _phrase = phrase;

        // Enrollment is atomic: a vault enrolled with a phrase that never reached storage is
        // unopenable by anyone, so tear it down rather than leave that behind.
        try {
          await _vault.put(_phraseRecord, Uint8List.fromList(utf8.encode(phrase)));
        } catch (_) {
          await _vault.destroy();
          _phrase = null;
          rethrow;
        }

      case SdkStep.unlock:
        await _vault.unlock();

      case SdkStep.recover:
        // Rewraps the primary path in the same operation, so the next unlock is biometric-only.
        await _vault.unlockWithRecovery();

      case SdkStep.lockedOut:
        // Retrying here would burn an attempt against a ladder that is already throttling.
        final until = (state as LockedOut).untilMs;
        throw VaultException(
          VaultErrorCode.denied,
          'too many failed recovery attempts; retry after '
          '${DateTime.fromMillisecondsSinceEpoch(until)}',
        );
    }
  }

  Future<RecoveryFactor> _recoveryFactor(RecoveryReason reason) async {
    final phrase = _phrase ?? await _options.vaultOptions.promptRecoveryPhrase(reason);
    if (!bip39.validateMnemonic(phrase.trim())) {
      // The BIP-39 checksum catches a mistyped word before it reaches the KDF. Not `denied`:
      // nothing was verified, so this must not spend one of the 11 attempts (spec 7.4).
      throw const VaultException.cancelled('that is not a valid 12-word phrase');
    }
    _phrase = phrase.trim();
    return RecoveryFactor.passphrase(_phrase!);
  }
}
