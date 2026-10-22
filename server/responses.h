#pragma once

#include <openssl/pem.h>
#include <string>
#include <vector>

#include "storage.h"

/// Reply to a KEY request by sending the server's public key file contents.
///
/// @param sd      The socket to write the key to
/// @param pubfile The public key file contents
///
/// @return false, since this request never halts the server
bool handle_key(int sd, const std::vector<uint8_t> &pubfile);

/// Reply to an ALL request with a newline-delimited list of all usernames.
///
/// @param sd      The socket to write the response to
/// @param storage The Storage object backing the auth table
/// @param aeskey  The AES key/iv to use for the response
/// @param u       The requesting user's name
/// @param p       The requesting user's password
/// @param req     The decrypted request body (unused by this handler)
///
/// @return false, since this request never halts the server
bool handle_all(int sd, Storage *storage, std::vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const std::vector<uint8_t> &req);

/// Reply to a SET request by storing new profile content for the user.
///
/// @param sd      The socket to write the response to
/// @param storage The Storage object backing the auth table
/// @param aeskey  The AES key/iv to use for the response
/// @param u       The requesting user's name
/// @param p       The requesting user's password
/// @param req     The decrypted request body: a length-prefixed content blob
///
/// @return false, since this request never halts the server
bool handle_set(int sd, Storage *storage, std::vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const std::vector<uint8_t> &req);

/// Reply to a GET request with another user's profile content.
///
/// @param sd      The socket to write the response to
/// @param storage The Storage object backing the auth table
/// @param aeskey  The AES key/iv to use for the response
/// @param u       The requesting user's name
/// @param p       The requesting user's password
/// @param req     The decrypted request body: the target username
///
/// @return false, since this request never halts the server
bool handle_get(int sd, Storage *storage, std::vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const std::vector<uint8_t> &req);

/// Reply to a REG request by trying to create a new user.
///
/// @param sd      The socket to write the response to
/// @param storage The Storage object backing the auth table
/// @param aeskey  The AES key/iv to use for the response
/// @param u       The requested username
/// @param p       The requested password
/// @param req     The decrypted request body (unused by this handler)
///
/// @return false, since this request never halts the server
bool handle_reg(int sd, Storage *storage, std::vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const std::vector<uint8_t> &req);

/// Reply to a BYE request, halting the server if the user authenticates.
///
/// @param sd      The socket to write the response to
/// @param storage The Storage object backing the auth table
/// @param aeskey  The AES key/iv to use for the response
/// @param u       The requesting user's name
/// @param p       The requesting user's password
/// @param req     The decrypted request body (unused by this handler)
///
/// @return true if the server should halt, false on an authentication error
bool handle_bye(int sd, Storage *storage, std::vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const std::vector<uint8_t> &req);

/// Reply to a SAV request by persisting storage to disk, if the user
/// authenticates.
///
/// @param sd      The socket to write the response to
/// @param storage The Storage object backing the auth table
/// @param aeskey  The AES key/iv to use for the response
/// @param u       The requesting user's name
/// @param p       The requesting user's password
/// @param req     The decrypted request body (unused by this handler)
///
/// @return false, since this request never halts the server
bool handle_sav(int sd, Storage *storage, std::vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const std::vector<uint8_t> &req);
