cmake_minimum_required(VERSION 3.5)

# ESP8266 RTOS SDK v3.4 contains dependencies with pre-3.5 policy versions.
# CMake 4 removed implicit compatibility with those versions, so retain the
# policy baseline expected by this legacy SDK.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
if(NOT DEFINED PROJECT_VER)
    set(PROJECT_VER "0.0.0-dev")
endif()
project(smart-door-opener)

# Keep the legacy SDK untouched; compile its HTTP client with fragment handling fixed.
set(http_client_source "$ENV{IDF_PATH}/components/esp_http_client/esp_http_client.c")
set(http_client_fixed "${CMAKE_BINARY_DIR}/esp_http_client_fixed.c")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
             "${http_client_source}" "${CMAKE_SOURCE_DIR}/tools/patch_http_client.py")
execute_process(COMMAND "${PYTHON}" "${CMAKE_SOURCE_DIR}/tools/patch_http_client.py"
                "${http_client_source}" "${http_client_fixed}"
                RESULT_VARIABLE http_patch_result)
if(NOT http_patch_result EQUAL 0)
    message(FATAL_ERROR "Could not fix legacy HTTP header parsing")
endif()
get_target_property(http_sources __idf_esp_http_client SOURCES)
list(FILTER http_sources EXCLUDE REGEX "(^|/)esp_http_client\\.c$")
set_property(TARGET __idf_esp_http_client PROPERTY SOURCES ${http_sources} "${http_client_fixed}")
