#pragma once

#include <openssl/pem.h>
#include <vector>

#include "storage.h"

/// Handle a freshly-accepted client connection: read its request, decrypt
/// and parse it, and dispatch to the right handler to satisfy it.
///
/// @param sd      The socket on which communication with the client happens
/// @param pri     The server's private RSA key
/// @param pub     The server's public key file contents, to send on request
/// @param storage The Storage object backing this request
///
/// @return true if the server should halt immediately, false otherwise
bool parse_request(int sd, EVP_PKEY *pri, const std::vector<uint8_t> &pub,
                   Storage *storage);
