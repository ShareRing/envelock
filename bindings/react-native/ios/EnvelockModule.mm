#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

// Bridges the Swift module into React Native's Objective-C registry.
//
// Method signatures must match `@objc(...)` in EnvelockModule.swift exactly. A mismatch is not
// a compile error - the method is simply never found at runtime.
@interface RCT_EXTERN_MODULE (RNEnvelock, RCTEventEmitter)

RCT_EXTERN_METHOD(create:(NSDictionary *)config
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(destroyInstance:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(state:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(enroll:(NSString *)kind
                  token:(nonnull NSNumber *)token
                  passphrase:(NSString *)passphrase
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(unlock:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(unlockWithRecovery:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(changeRecoveryFactor:(NSString *)kind
                  token:(nonnull NSNumber *)token
                  passphrase:(NSString *)passphrase
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(put:(NSString *)recordId
                  token:(nonnull NSNumber *)token
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(get:(NSString *)recordId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(remove:(NSString *)recordId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(list:(NSString *)prefix
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(lock:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(destroyVault:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(securityInfo:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

// Synchronous on purpose: it only hands a value to a waiting semaphore and must not be
// deferred behind other queued work.
RCT_EXTERN_METHOD(resolveCallback:(NSString *)requestId
                  token:(nonnull NSNumber *)token
                  text:(NSString *)text
                  errorCode:(NSString *)errorCode
                  errorMessage:(NSString *)errorMessage)

@end
