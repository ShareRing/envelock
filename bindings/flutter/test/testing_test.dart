import 'dart:typed_data';

import 'package:envelock/envelock.dart';
import 'package:envelock/testing.dart';
import 'package:flutter_test/flutter_test.dart';

/// Tests for the determinism harness itself.
///
/// It is the main thing keeping `providerMaterialMismatch` out of the issue tracker (spec
/// section 7.5), so it has to catch the bugs it claims to - and must not reject a correct provider.
Uint8List good() =>
    Uint8List.fromList(List.generate(32, (i) => (i * 37 + 11) % 256));

VaultOptions optionsWith(
  Future<KeyMaterial> Function(MaterialContext) getKeyMaterial, {
  String providerId = 'acme-v1',
}) =>
    VaultOptions(
      providerId: providerId,
      getKeyMaterial: getKeyMaterial,
      getRecoveryFactor: (_) async =>
          RecoveryFactor.highEntropy(Uint8List(32)),
    );

void main() {
  test('accepts a deterministic provider', () async {
    final report = await assertProviderDeterministic(
      optionsWith((_) async => KeyMaterial(material: good(), keyId: 'v1')),
      calls: 10,
    );
    expect(report.calls, 10);
    expect(report.keyId, 'v1');
    expect(report.fingerprint, matches(RegExp(r'^[0-9a-f]{8}$')));
  });

  test('rejects material that varies per call', () async {
    var n = 0;
    await expectLater(
      assertProviderDeterministic(
        optionsWith((_) async {
          final m = good();
          m[0] = n++;
          return KeyMaterial(material: m, keyId: 'v1');
        }),
        calls: 5,
      ),
      throwsA(
        isA<StateError>().having(
          (e) => e.message,
          'message',
          contains('different bytes on call'),
        ),
      ),
    );
  });

  test('rejects material that varies by reason', () async {
    await expectLater(
      assertProviderDeterministic(
        optionsWith((ctx) async {
          final m = good();
          if (ctx.reason == MaterialReason.rotate) m[31] ^= 0xff;
          return KeyMaterial(material: m, keyId: 'v1');
        }),
        calls: 6,
      ),
      throwsStateError,
    );
  });

  test('rejects a keyId that changes per call', () async {
    var n = 0;
    await expectLater(
      assertProviderDeterministic(
        optionsWith((_) async => KeyMaterial(material: good(), keyId: 'v${n++}')),
        calls: 3,
      ),
      throwsA(
        isA<StateError>().having((e) => e.message, 'message', contains('keyId')),
      ),
    );
  });

  test('rejects short, all-zero and constant material', () async {
    for (final bad in [
      Uint8List(31),
      Uint8List(32),
      Uint8List.fromList(List.filled(32, 0xab)),
    ]) {
      await expectLater(
        assertProviderDeterministic(
          optionsWith((_) async => KeyMaterial(material: bad, keyId: 'v1')),
          calls: 1,
        ),
        throwsStateError,
      );
    }
  });

  test('fingerprint is stable, salted, and does not reveal the material', () async {
    final a = await assertProviderDeterministic(
      optionsWith((_) async => KeyMaterial(material: good(), keyId: 'v1')),
      calls: 2,
    );
    final b = await assertProviderDeterministic(
      optionsWith((_) async => KeyMaterial(material: good(), keyId: 'v1')),
      calls: 2,
    );
    expect(a.fingerprint, b.fingerprint);

    final other = await assertProviderDeterministic(
      optionsWith(
        (_) async => KeyMaterial(material: good(), keyId: 'v1'),
        providerId: 'other',
      ),
      calls: 2,
    );
    expect(other.fingerprint, isNot(a.fingerprint));
    expect(a.fingerprint.length, 8);
  });

  test('detects material that changed across restarts', () async {
    final first = await assertProviderDeterministic(
      optionsWith((_) async => KeyMaterial(material: good(), keyId: 'v1')),
      calls: 2,
    );

    final changed = Uint8List.fromList(List.generate(32, (i) => (i * 13 + 5) % 256));
    await expectLater(
      assertProviderDeterministic(
        optionsWith((_) async => KeyMaterial(material: changed, keyId: 'v1')),
        calls: 2,
        acrossRestarts: first.fingerprint,
      ),
      throwsA(
        isA<StateError>()
            .having((e) => e.message, 'message', contains('across restarts')),
      ),
    );
  });

  test('supplies a distinct 32-byte nonce on every call', () async {
    final seen = <String>{};
    await assertProviderDeterministic(
      optionsWith((ctx) async {
        expect(ctx.nonce.length, 32);
        seen.add(ctx.nonce.join(','));
        return KeyMaterial(material: good(), keyId: 'v1');
      }),
      calls: 5,
    );
    expect(seen.length, 5);
  });
}
