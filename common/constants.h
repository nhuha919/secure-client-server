/// Protocol and cryptography constants shared by the client and server.

#pragma once

#include <openssl/sha.h>
#include <string>

/// Maximum length of a user name
const int LEN_UNAME = 32;

/// Maximum length of a user's actual password
const int LEN_PASSWORD = 32;

/// Length of a hashed password
const int LEN_PASSHASH = SHA256_DIGEST_LENGTH;

/// Maximum length of a user's profile content
const int LEN_PROFILE_FILE = 1048576;

/// Max length of a block before RSA encryption
const int LEN_RBLOCK_CONTENT = 128;

/// Length of a block after RSA encryption
const int LEN_RKBLOCK = 256;

/// Length of an RSA public key, as produced by OpenSSL for our key size
const int LEN_RSA_PUBKEY = 451;

/// Length of the password salt
const int LEN_SALT = 16;

/// Size of an RSA key, in bits
const int RSA_KEYSIZE = 2048;

/// Size of an AES key, in bytes
const int AES_KEYSIZE = 32;

/// Size of an AES initialization vector, in bytes
const int AES_IVSIZE = 16;

/// Request the server's public key
const std::string REQ_KEY = "KEY_";

/// Request the creation of a new user
const std::string REQ_REG = "REG_";

/// Force the server to stop
const std::string REQ_BYE = "EXIT";

/// Force the server to persist all its data to disk
const std::string REQ_SAV = "SAVE";

/// Set a user's profile content
const std::string REQ_SET = "SETP";

/// Get a user's profile content
const std::string REQ_GET = "GETP";

/// Get all user names
const std::string REQ_ALL = "ALL_";

/// Response code indicating that the command succeeded
const std::string RES_OK = "OK__";

/// Response code indicating that the registered user already exists
const std::string RES_ERR_USER_EXISTS = "ERR_USER_EXISTS";

/// Response code indicating that the client gave a bad username or password
const std::string RES_ERR_LOGIN = "ERR_LOGIN";

/// Response code indicating that the client request was improperly formatted
const std::string RES_ERR_REQ_FMT = "ERR_REQ_FMT";

/// Response code indicating that there is no data to send back
const std::string RES_ERR_NO_DATA = "ERR_NO_DATA";

/// Response code indicating that the user being looked up is invalid
const std::string RES_ERR_NO_USER = "ERR_NO_USER";

/// Response code indicating that the requested command doesn't exist
const std::string RES_ERR_INV_CMD = "ERR_INVALID_COMMAND";

/// Response code indicating that the client didn't get as much data as
/// expected
const std::string RES_ERR_XMIT = "ERR_XMIT";

/// Response code indicating that the request couldn't be decrypted with the
/// provided AES key
const std::string RES_ERR_CRYPTO = "ERR_CRYPTO";

/// Response code indicating that the server had an internal error, such as a
/// bad read from a file or a failure to generate a salt
const std::string RES_ERR_SERVER = "ERR_SERVER";

/// Response code indicating that something has not been implemented
const std::string RES_ERR_UNIMPLEMENTED = "ERR_UNIMPLEMENTED";

/// A unique 4-byte code used as a prefix each time an AuthTable entry is
/// written to disk
const std::string AUTHENTRY = "AUTH";
