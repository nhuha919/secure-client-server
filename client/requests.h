#pragma once

#include <openssl/rsa.h>
#include <string>

/// Request the server's public key, writing it to a local file once received.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param keyfile The file to which the key should be written
void req_key(int sd, const std::string &keyfile);

// NB: The remaining functions share a signature, so pointers to them can be
//     stored in an array and dispatched by command name.

/// Register a new user.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The server's public key
/// @param user    The username for the request
/// @param pass    The password for the request
void req_reg(int sd, EVP_PKEY *pubkey, const std::string &user,
             const std::string &pass, const std::string &);

/// Ask the server to stop.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The server's public key
/// @param user    The username for the request
/// @param pass    The password for the request
void req_bye(int sd, EVP_PKEY *pubkey, const std::string &user,
             const std::string &pass, const std::string &);

/// Ask the server to persist its data to disk.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The server's public key
/// @param user    The username for the request
/// @param pass    The password for the request
void req_sav(int sd, EVP_PKEY *pubkey, const std::string &user,
             const std::string &pass, const std::string &);

/// Set the calling user's profile content to the contents of a local file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The server's public key
/// @param user    The username for the request
/// @param pass    The password for the request
/// @param setfile The file whose contents should be uploaded
void req_set(int sd, EVP_PKEY *pubkey, const std::string &user,
             const std::string &pass, const std::string &setfile);

/// Fetch a user's profile content and save it to `<user>.file.dat`.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The server's public key
/// @param user    The username for the request
/// @param pass    The password for the request
/// @param getname The name of the user whose content should be fetched
void req_get(int sd, EVP_PKEY *pubkey, const std::string &user,
             const std::string &pass, const std::string &getname);

/// Fetch a newline-delimited list of all users and save it to a file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The server's public key
/// @param user    The username for the request
/// @param pass    The password for the request
/// @param allfile The file to which the result should be written
void req_all(int sd, EVP_PKEY *pubkey, const std::string &user,
             const std::string &pass, const std::string &allfile);
