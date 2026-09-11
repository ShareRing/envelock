require "yaml"

pubspec = YAML.load_file(File.join(__dir__, "..", "pubspec.yaml"))

Pod::Spec.new do |s|
  s.name         = "envelock"
  s.version      = pubspec["version"]
  s.summary      = pubspec["description"]
  s.license      = { :type => "Apache-2.0" }
  s.authors      = { "ShareRing" => "dev@sharering.network" }
  s.homepage     = pubspec["homepage"]
  s.source       = { :path => "." }
  s.platform     = :ios, "15.0"

  s.source_files = "Classes/**/*"

  s.dependency "Flutter"
  # The Secure Enclave shim and the generated UniFFI bindings. Pinned to this plugin's own
  # version: the two are released together from one tag, so anything else is a mismatch.
  #
  # EnvelockCore is not on CocoaPods trunk. The host app resolves it from the GitHub Release:
  #   pod 'EnvelockCore', :podspec =>
  #     'https://github.com/ShareRing/envelock/releases/download/v<version>/EnvelockCore.podspec'
  s.dependency "EnvelockCore", s.version.to_s

  s.pod_target_xcconfig = { "DEFINES_MODULE" => "YES" }
  s.swift_version = "5.9"
end
