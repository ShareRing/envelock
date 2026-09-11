#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------------------
// C ABI
//
// The platform modules are written in Swift and Kotlin, neither of which can talk to a C++
// class directly. They reach the same buffer registry through these functions.
// ---------------------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

/// Move bytes out of the registry.
///
/// On success writes a heap pointer and length, transfers ownership to the caller, and removes
/// the token. The caller **must** release it with `envelock_buffer_free`, which zeroizes.
/// Returns false for an unknown token - including one already taken, since every token is
/// single-use.
bool envelock_buffer_take(uint64_t token, uint8_t **out_data, size_t *out_len);

/// Copy bytes into the registry and return a single-use token for JavaScript to redeem.
uint64_t envelock_buffer_put(const uint8_t *data, size_t len);

/// Zeroize and release a buffer obtained from `envelock_buffer_take`.
void envelock_buffer_free(uint8_t *data, size_t len);

/// Discard a token without reading it, zeroizing whatever it held.
///
/// Called on error paths so an abandoned payload does not sit in memory until the process
/// exits.
void envelock_buffer_drop(uint64_t token);

/// Number of tokens currently outstanding. Test and diagnostic use only.
size_t envelock_buffer_count(void);

#ifdef __cplusplus
} // extern "C"
#endif
