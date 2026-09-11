#import <React/RCTBridgeModule.h>
#import <React/RCTCallInvoker.h>
#import <React/RCTCallInvokerModule.h>

#import "EnvelockJSI.h"

/// Installs envelock's JSI host functions into the JavaScript runtime.
///
/// A separate module from `RNEnvelock` because that one is implemented in Swift, and Swift
/// cannot touch JSI - it is a C++ API. This is the smallest possible ObjC++ shim.
///
/// ## Why `RCTCallInvoker` rather than the bridge
///
/// Reaching `RCTCxxBridge.runtime` directly is gone under the New Architecture: a bridgeless app
/// has no `RCTCxxBridge`, so a module written that way fails to build against 0.76+.
///
/// `RCTCallInvoker.invokeSync` runs a block on the JavaScript thread and hands over the
/// `jsi::Runtime`, which is what installation needs. Because a blocking synchronous native
/// method is *already* on the JS thread, the block runs inline rather than deadlocking.
@interface RNEnvelockJSI : NSObject <RCTBridgeModule, RCTCallInvokerModule>
@end

@implementation RNEnvelockJSI

RCT_EXPORT_MODULE(RNEnvelockJSI)

@synthesize callInvoker = _callInvoker;

/// JSI installation must happen on the JavaScript thread, which is where a blocking
/// synchronous method already runs.
+ (BOOL)requiresMainQueueSetup {
  return NO;
}

/// Synchronous by necessity: the host functions must exist on `global` before any JavaScript
/// that uses them runs.
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(install) {
  auto invoker = _callInvoker.callInvoker;
  if (invoker == nullptr) {
    // Returning false rather than throwing: the JS layer reports a clear error naming the
    // likely cause, which is far more useful than an ObjC exception crossing the bridge.
    return @NO;
  }

  // A plain local rather than `__block`: an ObjC block qualifier cannot be captured by a C++
  // lambda, and `invokeSync` takes a `std::function`.
  bool installed = false;
  invoker->invokeSync([&installed](facebook::jsi::Runtime &runtime) {
    envelock::install(runtime);
    installed = true;
  });

  return installed ? @YES : @NO;
}

@end
