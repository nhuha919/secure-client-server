#pragma once

#include <string>
#include <vector>

/// Storage is the interface for the server's data layer.  It owns the
/// authentication table (user names, salts, hashed passwords, and each
/// user's profile content) and exposes one method per client-facing
/// operation, so that request handlers only need to parse a request, call
/// into Storage, and format the result for the client.
///
/// Every operation returns a result_t.  When `succeeded` is false, `msg` is
/// an error code to send to the client.  When `succeeded` is true, `msg` is
/// usually RES_OK, and `data`, if non-empty, holds additional content to send
/// back.
class Storage {
public:
  /// result_t is returned from every Storage operation
  struct result_t {
    bool succeeded;            // True if the operation succeeded
    std::string msg;           // The message to send to the client
    std::vector<uint8_t> data; // Optional additional content to send
  };

  virtual ~Storage() {}

  /// Populate the Storage object from the file provided at construction
  /// time.  Begins by clearing any existing data.
  ///
  /// @return A result tuple.  A missing file is not an error.
  virtual result_t load_file() = 0;

  /// Create a new entry in the auth table.  Fails if the user already
  /// exists.  Otherwise, generates a salt, hashes the password, and stores
  /// an entry with empty content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  virtual result_t add_user(const std::string &user,
                            const std::string &pass) = 0;

  /// Set a user's profile content, if and only if the password matches.
  ///
  /// @param user    The user whose content is being set
  /// @param pass    The password used to authenticate
  /// @param content The data to store
  virtual result_t set_user_data(const std::string &user,
                                 const std::string &pass,
                                 const std::vector<uint8_t> &content) = 0;

  /// Fetch a copy of a user's profile content, if the requester's password
  /// matches.  Any authenticated user may request any other user's content.
  ///
  /// @param user The user making the request
  /// @param pass The password used to authenticate
  /// @param who  The user whose content is being fetched
  ///
  /// @return A result tuple.  Empty content is treated as an error.
  virtual result_t get_user_data(const std::string &user,
                                 const std::string &pass,
                                 const std::string &who) = 0;

  /// Return a newline-delimited list of all usernames in the auth table
  ///
  /// @param user The user making the request
  /// @param pass The password used to authenticate
  virtual result_t get_all_users(const std::string &user,
                                 const std::string &pass) = 0;

  /// Authenticate a user against the auth table
  ///
  /// @param user The user making the request
  /// @param pass The password used to authenticate
  virtual result_t auth(const std::string &user, const std::string &pass) = 0;

  /// Persist the entire Storage object to the file provided at construction
  /// time.  Writes to a temporary file first, then atomically renames it
  /// into place, so a crash mid-write can't corrupt existing data.
  virtual result_t save_file() = 0;
};

/// Create an empty Storage object backed by the given file.  Loading is a
/// separate step (load_file()), so construction never fails.
///
/// @param fname   The file to use for persistence
/// @param buckets The number of buckets in the underlying hash table
Storage *storage_factory(const std::string &fname, size_t buckets);
