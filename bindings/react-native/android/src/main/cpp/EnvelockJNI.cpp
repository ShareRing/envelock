#include <jni.h>

#include <vector>

#include "EnvelockJSI.h"

// JNI bridge for the JSI buffer registry.
//
// Two jobs: install the host functions into the JavaScript runtime, and give Kotlin the same
// access to the registry that Swift gets through the C ABI directly.

extern "C" JNIEXPORT jboolean JNICALL
Java_network_sharering_envelock_reactnative_EnvelockModule_nativeInstall(
    JNIEnv *, jobject, jlong runtimePointer) {
  if (runtimePointer == 0) {
    // Reported rather than thrown: the JS layer produces a clear message naming the likely
    // cause, which beats a JNI exception crossing the bridge.
    return JNI_FALSE;
  }
  envelock::install(*reinterpret_cast<facebook::jsi::Runtime *>(runtimePointer));
  return JNI_TRUE;
}

/// Redeem a token for its bytes. Returns null for an unknown or already-redeemed token.
extern "C" JNIEXPORT jbyteArray JNICALL
Java_network_sharering_envelock_reactnative_EnvelockModule_nativeTakeBuffer(
    JNIEnv *env, jobject, jlong token) {
  uint8_t *data = nullptr;
  size_t len = 0;
  if (!envelock_buffer_take(static_cast<uint64_t>(token), &data, &len)) {
    return nullptr;
  }

  jbyteArray result = env->NewByteArray(static_cast<jsize>(len));
  if (result != nullptr && len > 0) {
    env->SetByteArrayRegion(
        result, 0, static_cast<jsize>(len), reinterpret_cast<const jbyte *>(data));
  }
  // Always released, including when NewByteArray failed - otherwise a failed allocation would
  // leak the payload.
  envelock_buffer_free(data, len);
  return result;
}

/// Hand bytes to the registry and return the token JavaScript redeems.
extern "C" JNIEXPORT jlong JNICALL
Java_network_sharering_envelock_reactnative_EnvelockModule_nativePutBuffer(
    JNIEnv *env, jobject, jbyteArray bytes) {
  const jsize len = env->GetArrayLength(bytes);
  std::vector<uint8_t> copy(static_cast<size_t>(len));
  if (len > 0) {
    env->GetByteArrayRegion(bytes, 0, len, reinterpret_cast<jbyte *>(copy.data()));
  }
  return static_cast<jlong>(envelock_buffer_put(copy.data(), copy.size()));
}

/// Release a token nobody will redeem, zeroizing what it held.
extern "C" JNIEXPORT void JNICALL
Java_network_sharering_envelock_reactnative_EnvelockModule_nativeDropBuffer(
    JNIEnv *, jobject, jlong token) {
  envelock_buffer_drop(static_cast<uint64_t>(token));
}
