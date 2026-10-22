#include <string>

#include "authtableentry.h"
#include "sequentialmap.h"

using namespace std;

/// Create a SequentialMap instance that can be used as an authentication
/// table
///
/// @param buckets The number of buckets in the table
Map<string, AuthTableEntry> *authtable_factory(size_t buckets) {
  return new SequentialMap<string, AuthTableEntry>(buckets);
}
