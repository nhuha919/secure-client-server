#pragma once

#include "authtableentry.h"
#include "map.h"

/// Create a Map instance that can be used as an authentication table
///
/// @param _buckets The number of buckets in the table
Map<std::string, AuthTableEntry> *authtable_factory(size_t _buckets);
