#pragma once

#include <functional>
#include <sstream>
#include <string>
#include <vector>

/// A minimal, dependency-free unit test harness.  Tests register themselves
/// at static-initialization time via the TEST() macro below, and test_main.cc
/// runs every registered test and reports the results.

/// A single registered test: its name, and the function that runs it
struct TestCase {
  std::string name;
  std::function<void()> fn;
};

/// The global list of registered tests.  A function-local static avoids
/// relying on initialization order between translation units.
inline std::vector<TestCase> &test_registry() {
  static std::vector<TestCase> registry;
  return registry;
}

/// Registers a TestCase in the global registry when constructed.  TEST()
/// declares one of these per test, so registration happens automatically
/// before main() runs.
struct TestRegistrar {
  TestRegistrar(const std::string &name, std::function<void()> fn) {
    test_registry().push_back({name, fn});
  }
};

/// Thrown by CHECK()/CHECK_EQ() on failure, and caught by the test runner so
/// one failing check doesn't abort the whole test binary.
struct TestFailure {
  std::string message;
};

/// Define a test case.  Usage: TEST(my_test_name) { ...body... }
#define TEST(name)                                                           \
  void name();                                                               \
  static TestRegistrar registrar_##name(#name, name);                       \
  void name()

/// Fail the current test (with a message) if `cond` is false
#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      throw TestFailure{std::string("CHECK failed: ") + #cond + " at " +    \
                        __FILE__ + ":" + std::to_string(__LINE__)};         \
    }                                                                        \
  } while (0)

/// Fail the current test if `a` and `b` are not equal, reporting both values
#define CHECK_EQ(a, b)                                                       \
  do {                                                                       \
    auto _check_a = (a);                                                     \
    auto _check_b = (b);                                                     \
    if (!(_check_a == _check_b)) {                                           \
      std::ostringstream _oss;                                              \
      _oss << "CHECK_EQ failed: " << #a << " != " << #b << " at " << __FILE__ \
           << ":" << __LINE__;                                              \
      throw TestFailure{_oss.str()};                                        \
    }                                                                        \
  } while (0)
