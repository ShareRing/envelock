cmake_minimum_required(VERSION 3.22)
project(envelock_jsi)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(envelock_jsi SHARED
  ../cpp/EnvelockJSI.cpp
  src/main/cpp/EnvelockJNI.cpp
)

target_include_directories(envelock_jsi PRIVATE ../cpp)

# React Native publishes its prefab modules under these names; `jsi` carries the headers and
# the implementation the host functions link against.
find_package(ReactAndroid REQUIRED CONFIG)
target_link_libraries(envelock_jsi
  ReactAndroid::jsi
  android
  log
)
