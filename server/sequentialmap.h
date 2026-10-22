#pragma once

#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "map.h"

/// SequentialMap is a single-threaded implementation of the Map interface,
/// backed by a vector of key/value pairs.  Lookups, inserts, and removals are
/// all O(n).  It is a deliberately simple baseline: fine for a small,
/// single-threaded directory, and easy to swap out for a concurrent, bucketed
/// implementation if the server needs to scale.
///
/// @tparam K The type of the keys in this map
/// @tparam V The type of the values in this map
template <typename K, typename V> class SequentialMap : public Map<K, V> {
  /// The key/value pairs
  std::vector<std::pair<K, V>> entries;

public:
  /// Construct the map.  The bucket count is accepted for interface
  /// compatibility with bucketed implementations, but is unused here.
  SequentialMap(size_t) {}

  virtual ~SequentialMap() {}

  /// Clear the map
  virtual void clear() { entries.clear(); }

  /// Insert the provided key/value pair only if there is no mapping for the
  /// key yet.
  ///
  /// @param key The key to insert
  /// @param val The value to insert
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table
  virtual bool insert(K key, V val) {
    for (auto &entry : entries) {
      if (entry.first == key) {
        return false;
      }
    }

    entries.push_back(std::make_pair(key, val));
    return true;
  }

  /// Insert the provided key/value pair if there is no mapping for the key
  /// yet.  If there is a key, update the mapping by replacing the old value.
  ///
  /// @param key The key to upsert
  /// @param val The value to upsert
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table and was thus updated instead
  virtual bool upsert(K key, V val) {
    for (auto &entry : entries) {
      if (entry.first == key) {
        entry.second = val;
        return false;
      }
    }

    entries.emplace_back(key, val);
    return true;
  }

  /// Apply a function to the value associated with a given key.  The
  /// function is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with(K key, std::function<void(V &)> f) {
    for (auto &entry : entries) {
      if (entry.first == key) {
        f(entry.second);
        return true;
      }
    }
    return false;
  }

  /// Apply a function to the value associated with a given key.  The
  /// function is not allowed to modify the value.
  ///
  /// @param key The key whose value will be read
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with_readonly(K key, std::function<void(const V &)> f) {
    for (auto &entry : entries) {
      if (entry.first == key) {
        f(entry.second);
        return true;
      }
    }
    return false;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key The key whose mapping should be removed
  ///
  /// @return true if the key was found and the value unmapped, false
  ///         otherwise
  virtual bool remove(K key) {
    for (auto it = entries.begin(); it != entries.end(); ++it) {
      if (it->first == key) {
        entries.erase(it);
        return true;
      }
    }
    return false;
  }

  /// Apply a function to every key/value pair in the map.  The function is
  /// not allowed to modify keys or values.
  ///
  /// @param f The function to apply to each key/value pair
  virtual void do_all_readonly(std::function<void(const K, const V &)> f) {
    for (auto &entry : entries) {
      f(entry.first, entry.second);
    }
  }
};
