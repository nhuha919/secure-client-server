#include <cstring>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "../common/constants.h"
#include "../common/file.h"

#include "authtableentry.h"
#include "map.h"
#include "map_factories.h"
#include "storage.h"

using namespace std;

/// Append a 4-byte size to a buffer
template <class T> void add_size(vector<uint8_t> &res, T t) {
  uint32_t sz = t.size();
  res.insert(res.end(), (uint8_t *)&sz, ((uint8_t *)&sz) + sizeof(sz));
}

/// Append the contents of an iterable to a buffer
template <class T> void add_it(vector<uint8_t> &res, T t) {
  res.insert(res.end(), t.begin(), t.end());
}

/// Extract a string from a buffer
template <class Iter> string extract_string(Iter &it, size_t count) {
  string val(it, it + count);
  it += count;
  return val;
}

/// Extract a 4-byte size from a buffer
template <class Iter> uint32_t extract_size(Iter &it) {
  uint32_t val;
  memcpy(&val, &(*it), sizeof(uint32_t));
  it += sizeof(uint32_t);
  return val;
}

/// Extract a vector from a buffer
template <class Iter> vector<uint8_t> extract_vec(Iter &it, size_t count) {
  vector<uint8_t> vec(it, it + count);
  it += count;
  return vec;
}

/// Append a salt to a password, hash the result, and return it
///
/// @param pass The plain-text password to hash
/// @param salt The salt to combine with the password
///
/// @return The salted, hashed password
vector<uint8_t> hash_pass(string pass, vector<uint8_t> salt) {
  vector<uint8_t> buf(pass.begin(), pass.end());
  buf.insert(buf.end(), salt.begin(), salt.end());

  vector<uint8_t> hashpass(LEN_PASSHASH);
  SHA256(buf.data(), buf.size(), hashpass.data());
  return hashpass;
}

/// MyStorage implements the Storage interface on top of a single
/// authentication table.
class MyStorage : public Storage {
  /// The authentication table, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /// The file this Storage object loads from and persists to
  const string filename;

public:
  /// Construct an empty object and record the file it should load from.
  ///
  /// @param fname   The file to use for persistence
  /// @param buckets The number of buckets in the hash table
  MyStorage(const std::string &fname, size_t buckets)
      : auth_table(authtable_factory(buckets)), filename(fname) {}

  virtual ~MyStorage() {}

  /// Create a new entry in the auth table.  Fails if the user already
  /// exists.  Otherwise, generates a salt, hashes the password, and stores
  /// an entry with empty content.
  virtual result_t add_user(const string &user, const string &pass) {
    std::vector<uint8_t> salt(LEN_SALT);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
      return {false, RES_ERR_SERVER, {}};
    }

    AuthTableEntry entry{user, salt, hash_pass(pass, salt), {}};
    bool inserted = auth_table->insert(user, entry);
    if (!inserted) {
      return {false, RES_ERR_USER_EXISTS, {}};
    }
    return {true, RES_OK, {}};
  }

  /// Set a user's profile content, if and only if the password matches.
  virtual result_t set_user_data(const string &user, const string &pass,
                                 const vector<uint8_t> &content) {
    result_t auth_result = auth(user, pass);
    if (!auth_result.succeeded)
      return auth_result;

    auth_table->do_with(user,
                        [&](AuthTableEntry &entry) { entry.content = content; });

    return {true, RES_OK, {}};
  }

  /// Fetch a copy of a user's profile content, if the requester authenticates.
  virtual result_t get_user_data(const string &user, const string &pass,
                                 const string &who) {
    result_t auth_result = auth(user, pass);
    if (!auth_result.succeeded)
      return auth_result;

    vector<uint8_t> content;
    bool foundWho = auth_table->do_with_readonly(
        who, [&](const AuthTableEntry &entry) { content = entry.content; });

    if (!foundWho) {
      return {false, RES_ERR_NO_USER, {}};
    }
    if (content.empty()) {
      return {false, RES_ERR_NO_DATA, {}};
    }
    return {true, RES_OK, content};
  }

  /// Return a newline-delimited list of all usernames in the auth table.
  virtual result_t get_all_users(const string &user, const string &pass) {
    result_t auth_result = auth(user, pass);
    if (!auth_result.succeeded)
      return auth_result;

    string users;
    auth_table->do_all_readonly(
        [&](const string key, const AuthTableEntry &entry) { users += key + "\n"; });

    vector<uint8_t> data(users.begin(), users.end());
    return {true, RES_OK, data};
  }

  /// Authenticate a user by recomputing their salted password hash.
  virtual result_t auth(const string &user, const string &pass) {
    vector<uint8_t> hashpass;
    vector<uint8_t> salt;

    bool found = auth_table->do_with_readonly(user, [&](const AuthTableEntry &entry) {
      salt = entry.salt;
      hashpass = entry.pass_hash;
    });

    if (!found || hash_pass(pass, salt) != hashpass) {
      return {false, RES_ERR_LOGIN, {}};
    }

    return {true, RES_OK, {}};
  }

  /// Persist the entire auth table to disk.  Writes to a temporary file
  /// first, then atomically renames it into place.
  virtual result_t save_file() {
    vector<uint8_t> buffer;
    auth_table->do_all_readonly([&](const string key, const AuthTableEntry &entry) {
      add_it(buffer, AUTHENTRY);
      add_size(buffer, entry.username);
      add_size(buffer, entry.salt);
      add_size(buffer, entry.pass_hash);
      add_size(buffer, entry.content);
      add_it(buffer, entry.username);
      add_it(buffer, entry.salt);
      add_it(buffer, entry.pass_hash);
      add_it(buffer, entry.content);

      // AUTHENTRY (4) + four 4-byte lengths = 20 bytes of fixed header
      size_t entryLen = 20 + entry.username.size() + entry.salt.size() +
                         entry.pass_hash.size() + entry.content.size();
      size_t padding = (4 - (entryLen % 4)) % 4;
      for (size_t i = 0; i < padding; i++) {
        buffer.push_back(0);
      }
    });

    string tempfile = filename + ".tmp";
    if (!write_file(tempfile, buffer, 0)) {
      return {false, RES_ERR_SERVER, {}};
    }

    if (rename(tempfile.c_str(), filename.c_str()) != 0) {
      return {false, RES_ERR_SERVER, {}};
    }

    return {true, RES_OK, {}};
  }

  /// Load the auth table from disk, replacing any existing contents.  A
  /// missing file is not an error: it just means there's nothing to load.
  virtual result_t load_file() {
    auth_table->clear();

    if (!file_exists(filename)) {
      return {true, "File not found: " + filename, {}};
    }

    vector<uint8_t> buffer = load_entire_file(filename);
    auto it = buffer.begin();
    while (it != buffer.end()) {
      string header = extract_string(it, 4); // "AUTH"
      uint32_t lenU = extract_size(it);
      uint32_t lenS = extract_size(it);
      uint32_t lenP = extract_size(it);
      uint32_t lenC = extract_size(it);
      string u = extract_string(it, lenU);
      vector<uint8_t> s = extract_vec(it, lenS);
      vector<uint8_t> p = extract_vec(it, lenP);
      vector<uint8_t> c = extract_vec(it, lenC);

      size_t entryLen = 20 + lenU + lenS + lenP + lenC;
      size_t pad = (4 - (entryLen % 4)) % 4;
      it += pad;

      auth_table->insert(u, AuthTableEntry{u, s, p, c});
    }

    return {true, "Loaded: " + filename, {}};
  }
};

/// Create an empty Storage object backed by the given file.
Storage *storage_factory(const std::string &fname, size_t buckets) {
  return new MyStorage(fname, buckets);
}
