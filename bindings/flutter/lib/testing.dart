/// The determinism harness (spec 7.5).
///
/// Run this in CI and treat it as a prerequisite, not an optional extra. It is the main thing
/// keeping [VaultErrorCode.providerMaterialMismatch] out of your issue tracker.
///
/// A `getKeyMaterial` that returns different bytes on different calls makes the vault
/// permanently unopenable. The failure does not appear at enrollment - it appears days later,
/// on a device that has been working fine, and it looks exactly like data corruption.
library;

import 'dart:math';
import 'dart:typed_data';

import 'envelock.dart';

class DeterminismReport {
  const DeterminismReport({
    required this.calls,
    required this.keyId,
    required this.fingerprint,
  });

  final int calls;
  final String keyId;

  /// A stable, non-secret digest of the material.
  ///
  /// Deliberately not the material itself: a CI log is the last place a per-user pepper should
  /// end up. It is only ever compared against another fingerprint.
  final String fingerprint;
}

/// Assert that [getKeyMaterial] is deterministic.
///
/// [acrossRestarts] takes a `fingerprint` from a previous run in a *different process*. That is
/// the check that catches a value cached in a top-level variable, which looks perfectly stable
/// inside one process and bricks every vault on the next cold start.
Future<DeterminismReport> assertProviderDeterministic(
  VaultOptions options, {
  int calls = 10,
  List<MaterialReason> reasons = MaterialReason.values,
  String? acrossRestarts,
}) async {
  final random = Random.secure();
  Uint8List? firstMaterial;
  String? firstKeyId;

  for (var i = 0; i < calls; i++) {
    final reason = reasons[i % reasons.length];
    final nonce =
        Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));
    final result = await options.getKeyMaterial(
      MaterialContext(reason: reason, nonce: nonce, deadlineMs: 30000),
    );

    if (result.material.length < 32) {
      throw StateError(
        'getKeyMaterial returned ${result.material.length} bytes; at least 32 are required.',
      );
    }
    if (result.material.every((b) => b == 0)) {
      throw StateError(
        'getKeyMaterial returned all zeros - an uninitialised buffer, not a secret.',
      );
    }
    if (result.material.every((b) => b == result.material.first)) {
      throw StateError('getKeyMaterial returned a constant byte - this is not a secret.');
    }

    if (firstMaterial == null) {
      firstMaterial = result.material;
      firstKeyId = result.keyId;
      continue;
    }

    if (result.keyId != firstKeyId) {
      throw StateError(
        'getKeyMaterial returned keyId "${result.keyId}" on call ${i + 1} but "$firstKeyId" '
        'on call 1. A keyId changes only on deliberate rotation; varying it per call '
        'triggers an endless rewrap loop.',
      );
    }

    if (!_equal(result.material, firstMaterial)) {
      throw StateError(
        'getKeyMaterial returned different bytes on call ${i + 1} (reason ${reason.name}) '
        'than on call 1. It must be byte-identical every time.\n\n'
        'The usual causes: deriving from a bearer token (tokens rotate), including a '
        'timestamp, request id or nonce, or fingerprinting mutable device properties.',
      );
    }
  }

  if (firstMaterial == null) {
    throw ArgumentError('assertProviderDeterministic needs calls >= 1');
  }

  final fingerprint = _digest(firstMaterial, options.providerId);
  if (acrossRestarts != null && acrossRestarts != fingerprint) {
    throw StateError(
      'getKeyMaterial is stable within one process but changed across restarts. That is the '
      'signature of a value cached in memory rather than fetched or stored durably - it will '
      'brick every vault on the next cold start.',
    );
  }

  return DeterminismReport(
    calls: calls,
    keyId: firstKeyId!,
    fingerprint: fingerprint,
  );
}

bool _equal(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// FNV-1a over the material, salted by `providerId`.
///
/// A comparison token, never a security control - its only job is to let two runs say "same"
/// or "different" without printing a pepper into a CI log.
String _digest(Uint8List material, String providerId) {
  var h = 0x811c9dc5;
  for (final byte in [...providerId.codeUnits, ...material]) {
    h ^= byte;
    h = (h * 0x01000193) & 0xffffffff;
  }
  return h.toRadixString(16).padLeft(8, '0');
}
