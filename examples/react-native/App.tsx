/**
 * envelock on React Native.
 *
 * Walks the whole lifecycle so each step can be seen in isolation: enroll, lock, unlock,
 * write, read, recover, destroy. The log pane shows what actually happened, including which
 * errors are benign.
 *
 * ## What to watch for
 *
 * - **Unlock prompts once**, then reads records with no further prompt and no network.
 * - **Cancelling the biometric prompt** yields `cancelled`, not a lockout. Dismissing a
 *   prompt is normal behaviour, not a failed authentication.
 * - **Backgrounding the app** locks the vault. envelock wires that itself through `AppState`;
 *   zeroization happens in the Rust core, because dropping a JS reference gives no guarantee
 *   the key bytes leave memory (spec 11.3).
 * - **Record bytes never become strings.** They travel to native memory through JSI, so
 *   provider material is never sitting in an immutable JS string waiting for the GC.
 *
 * ## Run this on a physical device
 *
 * A simulator has no Secure Enclave and an emulator without a lock screen has no usable
 * Keystore. `securityInfo()` reports what you actually got, truthfully.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
  useColorScheme,
} from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

import SdkDemo from './AppSdk';
import {
  Vault,
  VaultError,
  outstandingBuffers,
  type SecurityEvent,
} from '@sharering/react-native-envelock';

import {
  demoRecoveryKey,
  demoRecoveryProvider,
  lastRecoveryReason,
  localDemoMaterialProvider,
  utf8Decode,
  utf8Encode,
} from './providers';

/**
 * Two demos, one app.
 *
 * **Vault directly** is this file: envelock as a standalone library, driven by the app itself.
 * **Inside an SDK** is `AppSdk.tsx`, where the same vault is baked into a product SDK
 * (`sdk.ts`) that exposes four calls and hides the vault entirely. envelock depends on neither
 * arrangement; both are just ways to consume it.
 */
export default function App(): React.JSX.Element {
  const [mode, setMode] = useState<'vault' | 'sdk'>('vault');

  return (
    <SafeAreaProvider>
      <View style={styles.modes}>
        <TouchableOpacity
          style={[styles.mode, mode === 'vault' && styles.modeOn]}
          onPress={() => setMode('vault')}>
          <Text style={styles.modeLabel}>Vault directly</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.mode, mode === 'sdk' && styles.modeOn]}
          onPress={() => setMode('sdk')}>
          <Text style={styles.modeLabel}>Inside an SDK</Text>
        </TouchableOpacity>
      </View>
      {mode === 'vault' ? <Demo /> : <SdkDemo />}
    </SafeAreaProvider>
  );
}

function Demo(): React.JSX.Element {
  const dark = useColorScheme() === 'dark';
  const vaultRef = useRef<Vault | undefined>(undefined);

  const [state, setState] = useState('...');
  const [log, setLog] = useState<string[]>([]);
  const [fatal, setFatal] = useState<string | undefined>();

  const append = useCallback((line: string) => {
    setLog((previous) => [line, ...previous].slice(0, 40));
  }, []);

  const refresh = useCallback(async () => {
    const vault = vaultRef.current;
    if (!vault) return;
    const next = await vault.state();
    setState(next.state === 'locked_out' ? `locked_out until ${next.untilMs}` : next.state);
  }, []);

  useEffect(() => {
    let disposed = false;

    (async () => {
      try {
        const vault = await Vault.create({
          providerId: 'envelock-demo',
          // Swap for backendMaterialProvider to see the real pattern; providers.ts explains
          // why a locally-stored pepper is not a second factor.
          getKeyMaterial: localDemoMaterialProvider,
          getRecoveryFactor: demoRecoveryProvider,
          onSecurityEvent: (event: SecurityEvent) => append(`- ${event.type}`),
        });

        if (disposed) {
          await vault.dispose();
          return;
        }
        vaultRef.current = vault;
        await refresh();
      } catch (e) {
        setFatal(String(e));
      }
    })();

    return () => {
      disposed = true;
      void vaultRef.current?.dispose();
      vaultRef.current = undefined;
    };
  }, [append, refresh]);

  /** Run a vault call and report the outcome. */
  const act = useCallback(
    async (label: string, body: (vault: Vault) => Promise<string>) => {
      const vault = vaultRef.current;
      if (!vault) return;

      try {
        append(`[ok] ${label} - ${await body(vault)}`);
      } catch (e) {
        const error = e as VaultError;
        append(
          error.code === 'cancelled'
            ? // Normal behaviour, and explicitly not a failed attempt (spec 7.4).
              `- ${label} - cancelled by user (not counted)`
            : `[x] ${label} - ${error.code}: ${error.message}`,
        );
      }
      await refresh();
    },
    [append, refresh],
  );

  if (fatal) {
    return (
      <SafeAreaView style={[styles.screen, dark && styles.screenDark]}>
        <ScrollView contentContainerStyle={styles.body}>
          <Text style={[styles.title, dark && styles.textDark]}>Could not open the vault</Text>
          <Text style={[styles.mono, dark && styles.textDark]}>{fatal}</Text>
        </ScrollView>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={[styles.screen, dark && styles.screenDark]}>
      <ScrollView contentContainerStyle={styles.body}>
        <Text style={[styles.title, dark && styles.textDark]}>envelock</Text>
        <Text style={[styles.state, dark && styles.textDark]}>state: {state}</Text>

        <Section title="Lifecycle" dark={dark}>
          <Action
            label="Enroll"
            onPress={() =>
              act('enroll', async (v) => {
                await v.enroll({ kind: 'highEntropy', bytes: demoRecoveryKey });
                return 'vault created, one prompt for enclave consent';
              })
            }
          />
          <Action
            label="Unlock"
            onPress={() =>
              act('unlock', async (v) => {
                await v.unlock();
                return 'one biometric prompt, cached material, no network';
              })
            }
          />
          <Action
            label="Lock"
            onPress={() =>
              act('lock', async (v) => {
                await v.lock();
                return 'DEK zeroized in Rust';
              })
            }
          />
        </Section>

        <Section title="Records" dark={dark}>
          <Action
            label="Write"
            onPress={() =>
              act('put', async (v) => {
                // A Uint8Array, not a string: these bytes reach native memory through JSI.
                await v.put('card:1', utf8Encode('4111 1111 1111 1111'));
                return 'wrote card:1';
              })
            }
          />
          <Action
            label="Read"
            onPress={() =>
              act('get', async (v) => {
                const bytes = await v.get('card:1');
                return bytes ? utf8Decode(bytes) : 'no such record';
              })
            }
          />
          <Action label="List" onPress={() => act('list', async (v) => `${await v.list()}`)} />
        </Section>

        <Section title="Recovery" dark={dark}>
          <Action
            label="Recover"
            onPress={() =>
              act('recover', async (v) => {
                await v.unlockWithRecovery();
                return `recovered (${lastRecoveryReason}); primary path rewrapped, so the next unlock is biometric-only`;
              })
            }
          />
          <Action
            label="Info"
            onPress={() =>
              act('security info', async (v) => {
                const info = await v.securityInfo();
                return `${info.hardwareBacking} keyId=${info.keyId} attempts=${info.failedAttempts}`;
              })
            }
          />
        </Section>

        <Section title="Diagnostics" dark={dark}>
          <Action
            label="Outstanding buffers"
            onPress={() =>
              act('buffers', async () => {
                // Should always be 0 at rest. A non-zero count means a token was created and
                // never redeemed - a leak of native memory holding a payload.
                const count = outstandingBuffers();
                return `${count} JSI buffer(s) outstanding${count === 0 ? ' (correct)' : ' - LEAK'}`;
              })
            }
          />
        </Section>

        <Section title="Danger" dark={dark}>
          <Action
            label="Destroy"
            onPress={() =>
              act('destroy', async (v) => {
                await v.destroy();
                return 'enclave key, envelope, cache and records deleted - irreversible';
              })
            }
          />
        </Section>

        <View style={[styles.logBox, dark && styles.logBoxDark]}>
          {log.length === 0 ? (
            <Text style={[styles.mono, dark && styles.textDark]}>Tap Enroll to begin.</Text>
          ) : (
            log.map((line, i) => (
              <Text key={i} style={[styles.mono, dark && styles.textDark]}>
                {line}
              </Text>
            ))
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

function Section({
  title,
  dark,
  children,
}: {
  title: string;
  dark: boolean;
  children: React.ReactNode;
}) {
  return (
    <View style={styles.section}>
      <Text style={[styles.sectionTitle, dark && styles.textDark]}>{title}</Text>
      <View style={styles.row}>{children}</View>
    </View>
  );
}

function Action({ label, onPress }: { label: string; onPress: () => void }) {
  return (
    <TouchableOpacity style={styles.button} onPress={onPress}>
      <Text style={styles.buttonLabel}>{label}</Text>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  modes: { flexDirection: 'row', gap: 8, padding: 8, backgroundColor: '#111114' },
  mode: { paddingHorizontal: 12, paddingVertical: 6, borderRadius: 6, backgroundColor: '#333' },
  modeOn: { backgroundColor: '#4338ca' },
  modeLabel: { color: 'white', fontSize: 12, fontWeight: '600' },
  screen: { flex: 1, backgroundColor: '#f7f7f9' },
  screenDark: { backgroundColor: '#111114' },
  body: { padding: 16, gap: 4 },
  title: { fontSize: 28, fontWeight: '600', marginBottom: 4 },
  state: { fontSize: 15, marginBottom: 8 },
  section: { marginTop: 12 },
  sectionTitle: { fontSize: 16, fontWeight: '600', marginBottom: 6 },
  row: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  button: {
    backgroundColor: '#4338ca',
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderRadius: 8,
  },
  buttonLabel: { color: 'white', fontWeight: '600' },
  logBox: {
    marginTop: 20,
    padding: 12,
    borderRadius: 8,
    backgroundColor: 'white',
    gap: 2,
  },
  logBoxDark: { backgroundColor: '#1c1c20' },
  mono: { fontFamily: 'Courier', fontSize: 11 },
  textDark: { color: '#e8e8ea' },
});
