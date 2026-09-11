// Tests for the buffer registry's C ABI.
//
// The JSI host functions need a JavaScript runtime to exercise, but the logic worth testing -
// token lifecycle, single-use semantics, zeroization - lives behind the C ABI and runs fine
// standalone. Build and run with cpp/run-tests.sh.

#include "EnvelockJSI.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {

void roundTripsBytes() {
  const uint8_t input[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x42};
  const uint64_t token = envelock_buffer_put(input, sizeof(input));
  assert(token != 0 && "zero is reserved for 'no buffer'");

  uint8_t *out = nullptr;
  size_t len = 0;
  assert(envelock_buffer_take(token, &out, &len));
  assert(len == sizeof(input));
  assert(std::memcmp(out, input, len) == 0);
  envelock_buffer_free(out, len);
}

// A stale token must not resurrect a payload that has already been consumed.
void tokensAreSingleUse() {
  const uint8_t input[] = {1, 2, 3};
  const uint64_t token = envelock_buffer_put(input, sizeof(input));

  uint8_t *out = nullptr;
  size_t len = 0;
  assert(envelock_buffer_take(token, &out, &len));
  envelock_buffer_free(out, len);

  assert(!envelock_buffer_take(token, &out, &len) && "a redeemed token must be gone");
}

void unknownTokensFail() {
  uint8_t *out = nullptr;
  size_t len = 0;
  assert(!envelock_buffer_take(999999, &out, &len));
  assert(!envelock_buffer_take(0, &out, &len));
}

// A zero-length record is legitimate and must not read as failure.
void handlesEmptyPayloads() {
  const uint64_t token = envelock_buffer_put(nullptr, 0);
  assert(token != 0);

  uint8_t *out = nullptr;
  size_t len = 0;
  assert(envelock_buffer_take(token, &out, &len));
  assert(len == 0);
  assert(out != nullptr && "an empty payload still needs a valid pointer");
  envelock_buffer_free(out, len);
}

// An abandoned payload must not sit in memory until the process exits.
void dropReleasesWithoutReading() {
  const size_t before = envelock_buffer_count();
  const uint8_t input[] = {9, 9, 9};
  const uint64_t token = envelock_buffer_put(input, sizeof(input));
  assert(envelock_buffer_count() == before + 1);

  envelock_buffer_drop(token);
  assert(envelock_buffer_count() == before);

  uint8_t *out = nullptr;
  size_t len = 0;
  assert(!envelock_buffer_take(token, &out, &len));
}

void droppingAnUnknownTokenIsHarmless() {
  envelock_buffer_drop(123456);
  envelock_buffer_drop(0);
}

void tokensAreUnique() {
  const uint8_t input[] = {7};
  std::vector<uint64_t> tokens;
  for (int i = 0; i < 100; i++) {
    tokens.push_back(envelock_buffer_put(input, sizeof(input)));
  }
  for (size_t i = 0; i < tokens.size(); i++) {
    for (size_t j = i + 1; j < tokens.size(); j++) {
      assert(tokens[i] != tokens[j]);
    }
  }
  for (uint64_t t : tokens) {
    envelock_buffer_drop(t);
  }
}

// Rust may hand material over from its own thread while JS redeems from another.
void isThreadSafe() {
  const size_t before = envelock_buffer_count();
  std::vector<std::thread> threads;

  for (int t = 0; t < 8; t++) {
    threads.emplace_back([] {
      for (int i = 0; i < 200; i++) {
        const uint8_t input[] = {1, 2, 3, 4};
        const uint64_t token = envelock_buffer_put(input, sizeof(input));
        uint8_t *out = nullptr;
        size_t len = 0;
        if (envelock_buffer_take(token, &out, &len)) {
          assert(len == 4);
          envelock_buffer_free(out, len);
        }
      }
    });
  }
  for (auto &thread : threads) {
    thread.join();
  }

  assert(envelock_buffer_count() == before && "every buffer should have been redeemed");
}

void freeingNullIsHarmless() { envelock_buffer_free(nullptr, 0); }

} // namespace

int main() {
  roundTripsBytes();
  tokensAreSingleUse();
  unknownTokensFail();
  handlesEmptyPayloads();
  dropReleasesWithoutReading();
  droppingAnUnknownTokenIsHarmless();
  tokensAreUnique();
  isThreadSafe();
  freeingNullIsHarmless();

  assert(envelock_buffer_count() == 0 && "no buffers should be left outstanding");
  std::printf("all buffer registry tests passed\n");
  return 0;
}
