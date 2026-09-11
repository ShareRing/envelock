import 'package:envelock/envelock.dart';
import 'package:envelock_demo/sharering_vault_sdk.dart';
import 'package:flutter_test/flutter_test.dart';

/// The SDK's whole decision surface: what one call does for each vault state.
///
/// `lockedOut` must not route to `recover`: retrying there burns an attempt against a ladder
/// that is already throttling, and 11 of those destroy the vault.
void main() {
  test('each vault state routes to one step', () {
    expect(stepFor(const Unlocked()), SdkStep.ready);
    expect(stepFor(const NotEnrolled()), SdkStep.enroll);
    expect(stepFor(const Locked()), SdkStep.unlock);
    expect(stepFor(const NeedsRecovery()), SdkStep.recover);
    expect(stepFor(const LockedOut(0)), SdkStep.lockedOut);
  });
}
