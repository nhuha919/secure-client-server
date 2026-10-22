#include <algorithm>
#include <cstring>

#include "../common/constants.h"
#include "../common/crypto.h"
#include "../common/net.h"

#include "parsing.h"
#include "responses.h"

using namespace std;

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

/// Check whether a fixed-size block is a (padded) KEY_ request
///
/// @param block The block of data to check
///
/// @return true if it is a key request, false otherwise
bool is_kblock(vector<uint8_t> &block) {
  if (block.size() != static_cast<size_t>(LEN_RKBLOCK))
    return false;

  if (!equal(REQ_KEY.begin(), REQ_KEY.end(), block.begin()))
    return false;

  for (size_t i = REQ_KEY.size(); i < block.size(); i++) {
    if (block[i] != 0)
      return false;
  }

  return true;
}

/// Handle a freshly-accepted client connection: read its request, decrypt
/// and parse it, and dispatch to the right handler to satisfy it.  Every
/// request (other than KEY_) arrives as a fixed-size RSA-encrypted block
/// containing the command, a per-request AES key, and the lengths of the
/// username/password/content, optionally followed by a variable-length
/// AES-encrypted content block.
///
/// @param sd      The socket on which communication with the client happens
/// @param pri     The server's private RSA key
/// @param pub     The server's public key file contents, to send on request
/// @param storage The Storage object backing this request
///
/// @return true if the server should halt immediately, false otherwise
bool parse_request(int sd, EVP_PKEY *pri, const vector<uint8_t> &pub,
                   Storage *storage) {
  vector<uint8_t> rblock(LEN_RKBLOCK);
  int len = reliable_get_to_eof_or_n(sd, rblock.begin(), LEN_RKBLOCK);

  if (len != LEN_RKBLOCK) {
    send_reliably(sd, RES_ERR_XMIT);
    return false;
  }

  if (is_kblock(rblock))
    return handle_key(sd, pub);

  vector<uint8_t> decrypt = rsa_decrypt(pri, rblock);
  if (decrypt.empty()) {
    send_reliably(sd, RES_ERR_CRYPTO);
    return false;
  }

  // cmd . aes_key . len(user) . len(pass) . len(content) . user . pass
  const size_t COMMANDLEN = REQ_KEY.size();
  const size_t KEYLEN = AES_KEYSIZE + AES_IVSIZE;
  const size_t HEADERLEN = COMMANDLEN + KEYLEN + 3 * sizeof(uint32_t);
  if (decrypt.size() < HEADERLEN) {
    send_reliably(sd, RES_ERR_REQ_FMT);
    return false;
  }

  auto it = decrypt.begin();
  string command = extract_string(it, COMMANDLEN);
  vector<uint8_t> aes_key(it, it + KEYLEN);
  it += KEYLEN;
  uint32_t lu = extract_size(it);
  uint32_t lp = extract_size(it);
  uint32_t lb = extract_size(it);

  auto send_err = [&](const string &msg) {
    send_reliably(sd, aes_crypt_msg(aes_key, msg, true));
    return false;
  };

  size_t remaining = static_cast<size_t>(decrypt.end() - it);
  if (lu > static_cast<uint32_t>(LEN_UNAME) ||
      lp > static_cast<uint32_t>(LEN_PASSWORD) ||
      static_cast<size_t>(lu) + lp > remaining ||
      lb > static_cast<uint32_t>(LEN_PROFILE_FILE) + sizeof(uint32_t) + AES_IVSIZE)
    return send_err(RES_ERR_REQ_FMT);

  string u = extract_string(it, lu);
  string p = extract_string(it, lp);

  vector<uint8_t> b;
  if (lb > 0) {
    vector<uint8_t> ablock(lb);
    int n = reliable_get_to_eof_or_n(sd, ablock.begin(), lb);

    if (n < 0 || static_cast<uint32_t>(n) != lb)
      return send_err(RES_ERR_XMIT);

    b = aes_crypt_msg(aes_key, ablock, false);
    if (b.empty())
      return send_err(RES_ERR_CRYPTO);
  }

  vector<string> commands = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  decltype(handle_reg) *handlers[] = {handle_reg, handle_bye, handle_sav,
                                      handle_set, handle_get, handle_all};
  for (size_t i = 0; i < commands.size(); ++i)
    if (command == commands[i])
      return handlers[i](sd, storage, aes_key, u, p, b);

  return send_err(RES_ERR_INV_CMD);
}
