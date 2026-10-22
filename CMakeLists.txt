cmake_minimum_required(VERSION 3.14)
project(secure_directory_service CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(BUILD_TESTS "Build the unit test suite" ON)
option(ENABLE_SANITIZERS "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

add_compile_options(-Wall -Wextra)

if(ENABLE_SANITIZERS)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# --- common_lib: sockets, file I/O, RSA/AES crypto, RAII helpers ------------
add_library(common_lib STATIC
  common/crypto.cc
  common/err.cc
  common/file.cc
  common/net.cc
)
target_link_libraries(common_lib PUBLIC OpenSSL::Crypto Threads::Threads)
target_include_directories(common_lib PUBLIC ${CMAKE_SOURCE_DIR})

# --- server_lib: storage, the auth-table map, request parsing/handling -----
add_library(server_lib STATIC
  server/my_storage.cc
  server/sequentialmap_factories.cc
  server/parsing.cc
  server/responses.cc
)
target_link_libraries(server_lib PUBLIC common_lib)

# --- executables -------------------------------------------------------------
add_executable(server server/server.cc)
target_link_libraries(server PRIVATE server_lib)

add_executable(client
  client/client.cc
  client/requests.cc
)
target_link_libraries(client PRIVATE common_lib)

# --- unit tests --------------------------------------------------------------
if(BUILD_TESTS)
  # Prefer a GoogleTest already installed on the system (e.g. via a package
  # manager); fetch and build it from source only if that's not available.
  find_package(GTest QUIET)
  if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG v1.15.2
    )
    # Match the rest of the project, and avoid overriding the parent's
    # compiler/linker settings on platforms that default differently.
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    add_library(GTest::gtest_main ALIAS gtest_main)
  endif()

  enable_testing()

  add_executable(unit_tests
    tests/test_crypto.cc
    tests/test_file.cc
    tests/test_map.cc
    tests/test_storage.cc
  )
  target_link_libraries(unit_tests PRIVATE server_lib GTest::gtest_main)

  include(GoogleTest)
  gtest_discover_tests(unit_tests)
endif()
