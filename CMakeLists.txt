cmake_minimum_required(VERSION 3.16)
project(VSecureTransfer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
  foreach(_cand /opt/homebrew/opt/openssl@3 /opt/homebrew/opt/openssl /usr/local/opt/openssl@3)
    if(IS_DIRECTORY "${_cand}/include/openssl")
      set(OPENSSL_ROOT_DIR "${_cand}" CACHE PATH "Homebrew OpenSSL prefix")
      break()
    endif()
  endforeach()
endif()

find_package(OpenSSL 3 REQUIRED)

option(VSECURE_BUILD_TESTS "Собирать юнит-тесты Catch2 (ctest)" ON)
option(VSECURE_ENABLE_COVERAGE "Флаги --coverage для gcc/clang (gcov/lcov)" OFF)

add_library(vsecure STATIC
  src/crypto.cpp
  src/metadata.cpp
  src/packet.cpp
  src/tcp.cpp
  src/replay.cpp
  src/event_journal.cpp
  src/modules_tz.cpp
)
target_include_directories(vsecure PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(vsecure PUBLIC OpenSSL::SSL OpenSSL::Crypto)

if(VSECURE_ENABLE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(vsecure PUBLIC --coverage -O0 -g)
  target_link_options(vsecure PUBLIC --coverage)
endif()

add_executable(vsecure_sender apps/sender_main.cpp src/sender_run.cpp)
target_link_libraries(vsecure_sender PRIVATE vsecure)

add_executable(vsecure_receiver apps/receiver_main.cpp src/receiver_run.cpp)
target_link_libraries(vsecure_receiver PRIVATE vsecure)

if(VSECURE_BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.4
  )
  FetchContent_MakeAvailable(Catch2)

  include(CTest)
  enable_testing()

  add_executable(vsecure_unit_tests
    tests/test_metadata.cpp
    tests/test_packet.cpp
    tests/test_replay.cpp
    tests/test_integrity.cpp
    tests/test_signing_blob.cpp
  )
  target_link_libraries(vsecure_unit_tests PRIVATE vsecure Catch2::Catch2WithMain)
  add_test(NAME vsecure_unit_tests COMMAND vsecure_unit_tests)
endif()
