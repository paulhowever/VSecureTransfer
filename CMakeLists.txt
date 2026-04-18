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

add_library(vsecure STATIC
  src/crypto.cpp
  src/metadata.cpp
  src/packet.cpp
  src/tcp.cpp
  src/replay.cpp
)
target_include_directories(vsecure PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(vsecure PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_executable(vsecure_sender apps/sender_main.cpp)
target_link_libraries(vsecure_sender PRIVATE vsecure)

add_executable(vsecure_receiver apps/receiver_main.cpp)
target_link_libraries(vsecure_receiver PRIVATE vsecure)
