#pragma once

#include "EnvelockBuffers.h"

#ifdef __cplusplus
#include <jsi/jsi.h>

namespace envelock {

/// Install envelock's JSI host functions into `runtime`.
///
/// Idempotent: installing twice replaces the previous functions rather than duplicating them.
/// Must be called on the JavaScript thread.
void install(facebook::jsi::Runtime &runtime);

} // namespace envelock
#endif
