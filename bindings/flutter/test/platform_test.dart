import 'package:envelock/envelock.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

/// Spec 6.4: web and desktop must fail with a named reason, not an opaque channel error.
///
/// The second group is what keeps the check honest. Pigeon never raises
/// `MissingPluginException`: an unhandled channel replies null and the generated code turns
/// that into `PlatformException('channel-error')`, which is also what a real transport fault
/// on a *supported* platform looks like. If [Vault.open] inferred the platform from that
/// error, a broken iOS build would claim iOS is unsupported.
void main() {
  final options = VaultOptions(
    providerId: 'test-v1',
    getKeyMaterial: (_) async => KeyMaterial(
      material: Uint8List(32),
      keyId: 'k1',
    ),
    getRecoveryFactor: (_) async => RecoveryFactor.passphrase('unused'),
  );

  tearDown(() => debugDefaultTargetPlatformOverride = null);

  for (final platform in [
    TargetPlatform.macOS,
    TargetPlatform.windows,
    TargetPlatform.linux,
    TargetPlatform.fuchsia,
  ]) {
    test('$platform refuses with platformUnsupported', () async {
      debugDefaultTargetPlatformOverride = platform;

      await expectLater(
        Vault.open(options),
        throwsA(
          isA<VaultException>()
              .having((e) => e.code, 'code', VaultErrorCode.platformUnsupported),
        ),
      );
    });
  }

  for (final platform in [TargetPlatform.iOS, TargetPlatform.android]) {
    test('$platform is never reported as unsupported', () async {
      TestWidgetsFlutterBinding.ensureInitialized();
      debugDefaultTargetPlatformOverride = platform;

      // No plugin is registered in a unit test, so this still fails - but on transport, and it
      // must not be mistaken for an unsupported platform.
      await expectLater(
        Vault.open(options),
        throwsA(
          isA<VaultException>().having(
            (e) => e.code,
            'code',
            isNot(VaultErrorCode.platformUnsupported),
          ),
        ),
      );
    });
  }
}
