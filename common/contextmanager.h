#pragma once

#include <functional>

/// ContextManager is a simple RAII helper for ensuring that cleanup code runs
/// when a function exits, regardless of which return path is taken.
class ContextManager {
  /// The cleanup code to run, usually a lambda
  std::function<void(void)> action;

  /// Lets the cleanup be cancelled if the caller changes their mind
  bool enabled = true;

public:
  /// Construct a ContextManager by providing a function to run on destruct
  ContextManager(std::function<void(void)> a) : action(a) {}

  /// Run the action when the ContextManager goes out of scope
  ~ContextManager() {
    if (enabled)
      action();
  }

  /// Cancel the action, so it does not run when this object goes out of scope
  void disable() { enabled = false; }
};
