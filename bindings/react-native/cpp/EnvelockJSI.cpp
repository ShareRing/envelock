#include "EnvelockJSI.h"

#include <cstring>
#include <map>
#include <mutex>
#include <utility>
#include <vector>

using namespace facebook;

namespace envelock {
namespace {

/// Overwrite a buffer in a way the optimiser is not permitted to remove.
///
/// A plain `memset` on memory that is about to be freed is dead-store-eliminated by every
/// modern compiler, which is exactly how "we zeroize the key" turns into a comment that is not
/// true. Writing through a volatile pointer forces the stores to happen.
void secureZero(void *data, size_t len) {
  auto *p = static_cast<volatile unsigned char *>(data);
  while (len-- > 0) {
    *p++ = 0;
  }
}

/// Holds byte payloads in transit between JavaScript and the platform module.
///
/// # Why this exists rather than base64
///
/// The TurboModule bridge can only carry strings. Base64 would cost an encode and a decode on
/// the JS thread and, worse, leave the material in an immutable JS `string` that cannot be
/// zeroized.
///
/// So JavaScript hands an `ArrayBuffer` straight to native memory and gets a numeric token back.
/// Nothing sensitive is ever a JS string, every payload is zeroized on release, and tokens are
/// single-use so a stale one cannot resurrect a consumed payload.
class BufferRegistry {
public:
  static BufferRegistry &shared() {
    static BufferRegistry instance;
    return instance;
  }

  uint64_t put(std::vector<uint8_t> bytes) {
    std::lock_guard<std::mutex> guard(mutex_);
    // Start at 1: zero is reserved so callers can use it as "no buffer".
    const uint64_t token = ++nextToken_;
    buffers_.emplace(token, std::move(bytes));
    return token;
  }

  bool take(uint64_t token, std::vector<uint8_t> &out) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto it = buffers_.find(token);
    if (it == buffers_.end()) {
      return false;
    }
    out = std::move(it->second);
    buffers_.erase(it);
    return true;
  }

  void drop(uint64_t token) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto it = buffers_.find(token);
    if (it == buffers_.end()) {
      return;
    }
    secureZero(it->second.data(), it->second.size());
    buffers_.erase(it);
  }

  size_t count() {
    std::lock_guard<std::mutex> guard(mutex_);
    return buffers_.size();
  }

private:
  std::mutex mutex_;
  std::map<uint64_t, std::vector<uint8_t>> buffers_;
  uint64_t nextToken_ = 0;
};

/// Backs a JavaScript `ArrayBuffer` with bytes owned by native code, zeroized on release.
///
/// The JS engine keeps this alive for as long as the `ArrayBuffer` is reachable, so the
/// destructor runs when the last JS reference is collected.
class OwnedBuffer : public jsi::MutableBuffer {
public:
  explicit OwnedBuffer(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {}

  ~OwnedBuffer() override { secureZero(bytes_.data(), bytes_.size()); }

  size_t size() const override { return bytes_.size(); }
  uint8_t *data() override { return bytes_.data(); }

private:
  std::vector<uint8_t> bytes_;
};

/// Largest payload accepted across the bridge, 64 MiB.
///
/// A hostile or buggy caller must not be able to make the app allocate without bound. Records
/// are cards and small blobs; anything near this ceiling is a mistake worth reporting loudly.
constexpr size_t kMaxPayloadBytes = 64u * 1024u * 1024u;

jsi::Value putBuffer(jsi::Runtime &rt, const jsi::Value *args, size_t count) {
  if (count < 1 || !args[0].isObject()) {
    throw jsi::JSError(rt, "envelock: putBuffer expects an ArrayBuffer");
  }
  auto object = args[0].getObject(rt);
  if (!object.isArrayBuffer(rt)) {
    throw jsi::JSError(rt, "envelock: putBuffer expects an ArrayBuffer");
  }

  auto buffer = object.getArrayBuffer(rt);
  const size_t size = buffer.size(rt);
  if (size > kMaxPayloadBytes) {
    throw jsi::JSError(rt, "envelock: payload exceeds the 64 MiB limit");
  }

  const uint8_t *data = buffer.data(rt);
  std::vector<uint8_t> bytes(data, data + size);
  const uint64_t token = BufferRegistry::shared().put(std::move(bytes));
  return jsi::Value(static_cast<double>(token));
}

jsi::Value takeBuffer(jsi::Runtime &rt, const jsi::Value *args, size_t count) {
  if (count < 1 || !args[0].isNumber()) {
    throw jsi::JSError(rt, "envelock: takeBuffer expects a token");
  }
  const auto token = static_cast<uint64_t>(args[0].getNumber());

  std::vector<uint8_t> bytes;
  if (!BufferRegistry::shared().take(token, bytes)) {
    throw jsi::JSError(rt, "envelock: unknown or already-redeemed buffer token");
  }

  return jsi::Value(
      rt, jsi::ArrayBuffer(rt, std::make_shared<OwnedBuffer>(std::move(bytes))));
}

jsi::Value dropBuffer(jsi::Runtime &, const jsi::Value *args, size_t count) {
  if (count >= 1 && args[0].isNumber()) {
    BufferRegistry::shared().drop(static_cast<uint64_t>(args[0].getNumber()));
  }
  return jsi::Value::undefined();
}

jsi::Value bufferCount(jsi::Runtime &, const jsi::Value *, size_t) {
  return jsi::Value(static_cast<double>(BufferRegistry::shared().count()));
}

using HostFn = jsi::Value (*)(jsi::Runtime &, const jsi::Value *, size_t);

void define(jsi::Runtime &rt, const char *name, unsigned argCount, HostFn fn) {
  auto propName = jsi::PropNameID::forAscii(rt, name);
  rt.global().setProperty(
      rt,
      name,
      jsi::Function::createFromHostFunction(
          rt,
          propName,
          argCount,
          [fn](jsi::Runtime &runtime,
               const jsi::Value &,
               const jsi::Value *args,
               size_t count) { return fn(runtime, args, count); }));
}

} // namespace

void install(jsi::Runtime &runtime) {
  define(runtime, "__envelockPutBuffer", 1, putBuffer);
  define(runtime, "__envelockTakeBuffer", 1, takeBuffer);
  define(runtime, "__envelockDropBuffer", 1, dropBuffer);
  define(runtime, "__envelockBufferCount", 0, bufferCount);
}

} // namespace envelock

// ---------------------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------------------

extern "C" {

bool envelock_buffer_take(uint64_t token, uint8_t **out_data, size_t *out_len) {
  if (out_data == nullptr || out_len == nullptr) {
    return false;
  }

  std::vector<uint8_t> bytes;
  if (!envelock::BufferRegistry::shared().take(token, bytes)) {
    return false;
  }

  // An empty payload is legitimate - a zero-length record - so hand back a valid pointer
  // rather than null, which the caller would read as failure.
  auto *copy = new uint8_t[bytes.empty() ? 1 : bytes.size()];
  if (!bytes.empty()) {
    std::memcpy(copy, bytes.data(), bytes.size());
    envelock::secureZero(bytes.data(), bytes.size());
  }

  *out_data = copy;
  *out_len = bytes.size();
  return true;
}

uint64_t envelock_buffer_put(const uint8_t *data, size_t len) {
  if (data == nullptr && len > 0) {
    return 0;
  }
  std::vector<uint8_t> bytes(data, data + len);
  return envelock::BufferRegistry::shared().put(std::move(bytes));
}

void envelock_buffer_free(uint8_t *data, size_t len) {
  if (data == nullptr) {
    return;
  }
  envelock::secureZero(data, len);
  delete[] data;
}

void envelock_buffer_drop(uint64_t token) {
  envelock::BufferRegistry::shared().drop(token);
}

size_t envelock_buffer_count(void) {
  return envelock::BufferRegistry::shared().count();
}

} // extern "C"
