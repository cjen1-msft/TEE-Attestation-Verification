cmake_minimum_required(VERSION 3.14)
project(tav_cpp_example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# 1. Find or fetch the tee-attestation-verification library
# ---------------------------------------------------------------------------
# In-tree: the repo root CMakeLists.txt is two levels up.
# Out-of-tree: fetch from GitHub via FetchContent.
get_filename_component(_repo_root "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

if(EXISTS "${_repo_root}/c/CMakeLists.txt" AND EXISTS "${_repo_root}/Cargo.toml")
    message(STATUS "In-tree build detected – using repo at ${_repo_root}")
    add_subdirectory("${_repo_root}/c" "${CMAKE_CURRENT_BINARY_DIR}/tee_attestation_verification")
else()
    include(FetchContent)
    message(STATUS "Fetching tee-attestation-verification from GitHub …")
    FetchContent_Declare(
        tee_attestation_verification_repo
        GIT_REPOSITORY https://github.com/microsoft/TEE-Attestation-Verification.git
        GIT_TAG        main
    )
    FetchContent_Populate(tee_attestation_verification_repo)
    add_subdirectory(
        "${tee_attestation_verification_repo_SOURCE_DIR}/c"
        "${tee_attestation_verification_repo_BINARY_DIR}")
endif()

# ---------------------------------------------------------------------------
# 2. Build the C++ example
# ---------------------------------------------------------------------------
add_executable(verify_example main.cpp)
target_link_libraries(verify_example PRIVATE tee_attestation_verification)
