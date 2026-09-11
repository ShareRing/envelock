import { stepFor } from '../sdkState';

/**
 * The SDK's whole decision surface: what one call does for each vault state.
 *
 * `locked_out` must not route to `recover`: retrying there burns an attempt against a ladder
 * that is already throttling, and 11 of those destroy the vault.
 */
test('each vault state routes to one step', () => {
  expect(stepFor({ state: 'unlocked' })).toBe('ready');
  expect(stepFor({ state: 'not_enrolled' })).toBe('enroll');
  expect(stepFor({ state: 'locked' })).toBe('unlock');
  expect(stepFor({ state: 'needs_recovery' })).toBe('recover');
  expect(stepFor({ state: 'locked_out', untilMs: 0 })).toBe('lockedOut');
});
