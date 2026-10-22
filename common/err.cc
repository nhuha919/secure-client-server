#include <system_error>

#include "err.h"

using namespace std;

/// Create a string representation of the error message associated with the
/// given errno
///
/// @param err The error number to use when producing an error message
///
/// @return A string representing the error message
string msg_from_errno(int err) {
  return std::system_category().message(err);
}
