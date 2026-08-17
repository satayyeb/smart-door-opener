cmake_minimum_required(VERSION 3.5)

# ESP8266 RTOS SDK v3.4 contains dependencies with pre-3.5 policy versions.
# CMake 4 removed implicit compatibility with those versions, so retain the
# policy baseline expected by this legacy SDK.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(smart-door-opener)
