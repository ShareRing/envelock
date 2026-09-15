import 'package:envelock/envelock.dart';
import 'package:envelock/src/messages.g.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// envelock holds any number of vaults, matching the native iOS and Android libraries where a
/// vault is just an object. An app can run its own beside one belonging to an SDK it embeds.
///
/// The bug this guards against is a screen swap. Flutter runs the incoming child's `initState`
/// before unmounting the outgoing one, and `State.dispose` cannot await, so the outgoing
/// `dispose()` could reach the platform *after* the incoming `open()`. While the plugin held a
/// single vault, that destroyed the one that had just replaced it and every in-flight callback
/// failed as `unavailable` - which reads as a provider outage and points nowhere near the
/// cause.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const codec = EnvelockHostApi.pigeonChannelCodec;
  late List<String> disposed;
  late int created;

  void mock(String method, Object? Function(List<Object?> args) body) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMessageHandler(
      'dev.flutter.pigeon.envelock.EnvelockHostApi.$method',
      (ByteData? message) async => codec.encodeMessage(
        <Object?>[body((codec.decodeMessage(message) as List<Object?>?) ?? <Object?>[])],
      ),
    );
  }

  VaultOptions optionsFor(String providerId) => VaultOptions(
        providerId: providerId,
        getKeyMaterial: (_) async =>
            KeyMaterial(material: Uint8List(32), keyId: 'k1'),
        getRecoveryFactor: (_) async => RecoveryFactor.passphrase('unused'),
      );

  setUp(() {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    disposed = [];
    created = 0;
    mock('create', (args) {
      final config = args.first! as WireVaultConfig;
      return WireVaultHandle(
        vaultId: 'vault-${created++}',
        directory: '/tmp/${config.providerId}',
      );
    });
    // Answers only for a vault the fake still considers open, the way the plugin's map does.
    mock('state', (args) {
      final id = args.first! as String;
      if (disposed.contains(id)) throw StateError('no such vault: $id');
      return WireStateResult(state: WireVaultState.notEnrolled);
    });
    mock('dispose', (args) {
      disposed.add(args.first! as String);
      return null;
    });
  });

  tearDown(() => debugDefaultTargetPlatformOverride = null);

  test('each vault gets its own id', () async {
    final first = await Vault.open(optionsFor('demo'));
    final second = await Vault.open(optionsFor('sdk'));

    expect(first.directory, '/tmp/demo');
    expect(second.directory, '/tmp/sdk');
    expect((await first.state()).runtimeType, NotEnrolled);
    expect((await second.state()).runtimeType, NotEnrolled);
  });

  test('disposing one vault leaves the other working', () async {
    final first = await Vault.open(optionsFor('demo'));
    final second = await Vault.open(optionsFor('sdk'));

    // This is the outgoing screen unmounting after the incoming one opened.
    await first.dispose();

    expect(disposed, ['vault-0'], reason: 'only the vault asked for');
    expect((await second.state()).runtimeType, NotEnrolled);
  });

  test('a disposed vault says so rather than reaching the platform', () async {
    final only = await Vault.open(optionsFor('demo'));
    await only.dispose();

    await expectLater(
      only.state(),
      throwsA(isA<VaultException>()
          .having((e) => e.code, 'code', VaultErrorCode.misconfigured)),
    );
    expect(disposed, ['vault-0'], reason: 'no second dispose reaches native');
  });
}
