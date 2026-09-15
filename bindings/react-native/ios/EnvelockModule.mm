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

RCT_EXTERN_METHOD(destroyInstance:(NSString *)vaultId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(state:(NSString *)vaultId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(enroll:(NSString *)vaultId
                  kind:(NSString *)kind
                  token:(nonnull NSNumber *)token
                  passphrase:(NSString *)passphrase
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(unlock:(NSString *)vaultId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(unlockWithRecovery:(NSString *)vaultId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(changeRecoveryFactor:(NSString *)vaultId
                  kind:(NSString *)kind
                  token:(nonnull NSNumber *)token
                  passphrase:(NSString *)passphrase
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(put:(NSString *)vaultId
                  recordId:(NSString *)recordId
                  token:(nonnull NSNumber *)token
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(get:(NSString *)vaultId
                  recordId:(NSString *)recordId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(remove:(NSString *)vaultId
                  recordId:(NSString *)recordId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(list:(NSString *)vaultId
                  prefix:(NSString *)prefix
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(lock:(NSString *)vaultId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(destroyVault:(NSString *)vaultId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(securityInfo:(NSString *)vaultId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

// Synchronous on purpose: it only hands a value to a waiting semaphore and must not be
// deferred behind other queued work.
RCT_EXTERN_METHOD(resolveCallback:(NSString *)requestId
                  token:(nonnull NSNumber *)token
                  text:(NSString *)text
                  errorCode:(NSString *)errorCode
                  errorMessage:(NSString *)errorMessage)

@end
