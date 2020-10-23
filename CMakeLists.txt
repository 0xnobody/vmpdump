cmake_minimum_required(VERSION 3.15)

project(VMPDump)

include(FetchContent)

FetchContent_Declare(
    VTIL-NativeLifters
    GIT_REPOSITORY https://github.com/vtil-project/VTIL-NativeLifters
    GIT_TAG        39e9da9966790d9e117de6af927ef9abb7e7519e
    GIT_SHALLOW    false
)
FetchContent_MakeAvailable(VTIL-NativeLifters)

# Hotfix for VTIL-Core on Windows
target_compile_definitions(VTIL-Common PUBLIC NOMINMAX)

add_subdirectory(VMPDump)
add_subdirectory(VMPDump_Tester)
