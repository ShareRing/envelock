import 'dart:convert';
import 'dart:typed_data';

import 'package:envelock/envelock.dart';
import 'package:flutter/material.dart';

import 'providers.dart';
import 'sdk_demo_screen.dart';

/// envelock on Flutter.
///
/// Walks the whole lifecycle so each step can be seen in isolation: enroll, lock, unlock,
/// write, read, recover, destroy. The log pane shows what actually happened, including which
/// errors are benign.
///
/// ## What to watch for
///
/// - **Unlock prompts once**, then reads records with no further prompt and no network.
/// - **Cancelling the biometric prompt** produces `cancelled`, not a lockout. Dismissing a
///   prompt is normal behaviour, not a failed authentication.
/// - **Backgrounding the app** locks the vault. That is wired by envelock itself through a
///   `WidgetsBindingObserver`; zeroization happens inside the Rust core, because dropping a
///   Dart reference gives no guarantee the key bytes leave memory (spec 11.3).
void main() {
  runApp(const DemoApp());
}

class DemoApp extends StatelessWidget {
  const DemoApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'envelock',
        theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
        darkTheme: ThemeData(
          colorSchemeSeed: Colors.indigo,
          brightness: Brightness.dark,
          useMaterial3: true,
        ),
        home: const DemoHome(),
      );
}

/// Two demos, one app.
///
/// **Vault directly** is [DemoScreen]: envelock as a standalone library, driven by the app
/// itself. **Inside an SDK** is [SdkDemoScreen], where the same vault is baked into a product
/// SDK (`lib/sharering_vault_sdk.dart`) that exposes four calls and hides the vault entirely.
/// envelock depends on neither arrangement; both are just ways to consume it.
class DemoHome extends StatefulWidget {
  const DemoHome({super.key});

  @override
  State<DemoHome> createState() => _DemoHomeState();
}

class _DemoHomeState extends State<DemoHome> {
  int _tab = 0;

  @override
  Widget build(BuildContext context) => Scaffold(
        body: _tab == 0 ? const DemoScreen() : const SdkDemoScreen(),
        bottomNavigationBar: NavigationBar(
          selectedIndex: _tab,
          onDestinationSelected: (index) => setState(() => _tab = index),
          destinations: const [
            NavigationDestination(
              icon: Icon(Icons.lock_outline),
              label: 'Vault directly',
            ),
            NavigationDestination(
              icon: Icon(Icons.inventory_2_outlined),
              label: 'Inside an SDK',
            ),
          ],
        ),
      );
}

class DemoScreen extends StatefulWidget {
  const DemoScreen({super.key});

  @override
  State<DemoScreen> createState() => _DemoScreenState();
}

class _DemoScreenState extends State<DemoScreen> {
  final _recovery = DemoRecoveryProvider();
  final _log = <String>[];

  Vault? _vault;
  VaultState? _state;
  String? _fatal;

  @override
  void initState() {
    super.initState();
    _open();
  }

  @override
  void dispose() {
    _vault?.dispose();
    super.dispose();
  }

  Future<void> _open() async {
    try {
      final vault = await Vault.open(
        VaultOptions(
          providerId: 'envelock-demo',
          // Swap for BackendMaterialProvider to see the real pattern; see providers.dart for
          // why a locally-stored pepper is not a second factor.
          getKeyMaterial: LocalDemoMaterialProvider().call,
          getRecoveryFactor: _recovery.call,
          onSecurityEvent: (event) => _append('- $event'),
        ),
      );
      setState(() => _vault = vault);
      await _refresh();
    } catch (e) {
      setState(() => _fatal = '$e');
    }
  }

  void _append(String line) {
    if (!mounted) return;
    setState(() {
      _log.insert(0, line);
      if (_log.length > 40) _log.removeLast();
    });
  }

  Future<void> _refresh() async {
    final vault = _vault;
    if (vault == null) return;
    final state = await vault.state();
    if (mounted) setState(() => _state = state);
  }

  Future<void> _act(String label, Future<String> Function(Vault) body) async {
    final vault = _vault;
    if (vault == null) return;

    try {
      _append('[ok] $label - ${await body(vault)}');
    } on VaultException catch (e) {
      // Cancelling is normal behaviour and explicitly not a failed attempt (spec 7.4).
      _append(
        e.code == VaultErrorCode.cancelled
            ? '- $label - cancelled by user (not counted)'
            : '[x] $label - ${e.code.name}: ${e.message ?? ''}',
      );
    }
    await _refresh();
  }

  String _describe(VaultState? state) => switch (state) {
        null => '...',
        NotEnrolled() => 'notEnrolled',
        Locked() => 'locked',
        Unlocked() => 'unlocked',
        LockedOut(:final untilMs) => 'lockedOut until $untilMs',
        NeedsRecovery() => 'needsRecovery',
      };

  @override
  Widget build(BuildContext context) {
    final fatal = _fatal;
    if (fatal != null) {
      return Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Text('Could not open the vault:\n\n$fatal'),
          ),
        ),
      );
    }

    return Scaffold(
      appBar: AppBar(title: Text('envelock - ${_describe(_state)}')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _section('Lifecycle'),
          _row([
            _button('Enroll', () => _act('enroll', (v) async {
                  await v.enroll(
                    RecoveryFactor.highEntropy(DemoRecoveryProvider.demoKey),
                  );
                  return 'vault created, one prompt for enclave consent';
                })),
            _button('Unlock', () => _act('unlock', (v) async {
                  await v.unlock();
                  return 'one biometric prompt, cached material, no network';
                })),
            _button('Lock', () => _act('lock', (v) async {
                  await v.lock();
                  return 'DEK zeroized in Rust';
                })),
          ]),

          _section('Records'),
          _row([
            _button('Write', () => _act('put', (v) async {
                  await v.put(
                    'card:1',
                    Uint8List.fromList(utf8.encode('4111 1111 1111 1111')),
                  );
                  return 'wrote card:1';
                })),
            _button('Read', () => _act('get', (v) async {
                  final bytes = await v.get('card:1');
                  return bytes == null ? 'no such record' : utf8.decode(bytes);
                })),
            _button('List', () => _act('list', (v) async => '${await v.list()}')),
          ]),

          _section('Recovery'),
          _row([
            _button('Recover', () => _act('recover', (v) async {
                  await v.unlockWithRecovery();
                  return 'recovered (${_recovery.lastReason?.name}); primary path rewrapped, '
                      'so the next unlock is biometric-only';
                })),
            _button('Info', () => _act('security info', (v) async {
                  final i = await v.securityInfo();
                  return '${i.hardwareBacking.name} '
                      '(hardware=${i.hardwareBacking.isHardwareBacked}) keyId=${i.keyId}';
                })),
          ]),

          _section('Danger'),
          _button('Destroy', () => _act('destroy', (v) async {
                await v.destroy();
                return 'enclave key, envelope, cache and records deleted - irreversible';
              })),

          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: _log.isEmpty
                    ? [const Text('Tap Enroll to begin.')]
                    : _log
                        .map((line) => Padding(
                              padding: const EdgeInsets.symmetric(vertical: 2),
                              child: Text(line, style: const TextStyle(fontSize: 12)),
                            ))
                        .toList(),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _section(String title) => Padding(
        padding: const EdgeInsets.only(top: 12, bottom: 4),
        child: Text(title, style: Theme.of(context).textTheme.titleMedium),
      );

  Widget _row(List<Widget> children) => Wrap(spacing: 8, runSpacing: 8, children: children);

  Widget _button(String label, VoidCallback onPressed) =>
      FilledButton(onPressed: onPressed, child: Text(label));
}
