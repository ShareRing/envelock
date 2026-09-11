/**
 * What the SDK does next, given what the vault says it is.
 *
 * Its own file so the routing can be tested without loading the native module - the import
 * below is type-only and erased at runtime.
 */
import type { VaultState } from '@sharering/react-native-envelock';

export type SdkStep = 'ready' | 'enroll' | 'unlock' | 'recover' | 'lockedOut';

export function stepFor(state: VaultState): SdkStep {
  switch (state.state) {
    case 'unlocked':
      return 'ready';
    case 'not_enrolled':
      return 'enroll';
    case 'locked':
      return 'unlock';
    case 'needs_recovery':
      return 'recover';
    case 'locked_out':
      return 'lockedOut';
  }
}
