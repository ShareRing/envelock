require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "envelock-react-native"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.license      = "Apache-2.0"
  s.authors      = { "ShareRing" => "dev@sharering.network" }
  s.homepage     = "https://github.com/ShareRing/envelock"
  s.platforms    = { :ios => "15.0" }
  s.source       = { :git => "https://github.com/ShareRing/envelock.git", :tag => "v#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift}", "cpp/**/*.{h,cpp}"

  # `EnvelockBuffers.h` is the C ABI the Swift module calls; it must be a public header so the
  # generated module map exposes it to Swift. `EnvelockJSI.h` pulls in <jsi/jsi.h>, which Swift
  # cannot parse, so it stays private and is used only from the ObjC++ installer.
  s.public_header_files = "cpp/EnvelockBuffers.h"
  s.pod_target_xcconfig = {
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++17",
    "HEADER_SEARCH_PATHS" => "\"$(PODS_ROOT)/Headers/Public/React-jsi\" \"$(PODS_TARGET_SRCROOT)/cpp\""
  }

  s.dependency "React-Core"
  s.dependency "React-jsi"
  # The Secure Enclave shim and the generated UniFFI bindings. Pinned to this package's own
  # version: the two are released together from one tag, so anything else is a mismatch.
  #
  # EnvelockCore is not on CocoaPods trunk. The host app resolves it from the GitHub Release:
  #   pod 'EnvelockCore', :podspec =>
  #     'https://github.com/ShareRing/envelock/releases/download/v<version>/EnvelockCore.podspec'
  s.dependency "EnvelockCore", s.version.to_s
end
