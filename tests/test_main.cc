#include <iostream>

#include "test_framework.h"

/// Run every test registered via TEST() and report pass/fail counts.  Exits
/// non-zero if any test failed, so `make test` fails the build.
int main() {
  int passed = 0, failed = 0;

  for (auto &tc : test_registry()) {
    try {
      tc.fn();
      std::cout << "[PASS] " << tc.name << "\n";
      ++passed;
    } catch (const TestFailure &f) {
      std::cout << "[FAIL] " << tc.name << ": " << f.message << "\n";
      ++failed;
    } catch (const std::exception &e) {
      std::cout << "[FAIL] " << tc.name << ": uncaught exception: " << e.what()
                << "\n";
      ++failed;
    }
  }

  std::cout << "\n" << passed << " passed, " << failed << " failed\n";
  return failed == 0 ? 0 : 1;
}
