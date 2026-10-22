#include <cstring>
#include <iostream>

#include "../common/constants.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"

#include "requests.h"

using namespace std;

/// Used in place of constructing an empty vector argument at each call site
vector<uint8_t> empty_vec;

/// Append a 4-byte size to a buffer
template <class T> void add_size(vector<uint8_t> &res, T t) {
  uint32_t sz = t.size();
  res.insert(res.end(), (uint8_t *)&sz, ((uint8_t *)&sz) + sizeof(sz));
}

/// Append the contents of an iterable to a buffer
template <class T> void add_it(vector<uint8_t> &res, T t) {
  res.insert(res.end(), t.begin(), t.end());
}

/// If a buffer holds RES_OK . len(content) . content, write `content` to a
/// file; otherwise just print the buffer as a status message.
///
/// @param buf      The buffer holding a server response
/// @param filename The file to write the content to
void send_result_to_file(const vector<uint8_t> &buf, const string &filename) {
  uint32_t skip = sizeof(uint32_t) + RES_OK.length();
  if (buf.size() >= skip &&
      !strncmp((char *)buf.data(), RES_OK.c_str(), RES_OK.length())) {
    uint32_t len = *(uint32_t *)&buf[RES_OK.length()];
    if (len != buf.size() - skip) {
      cout << RES_ERR_XMIT << endl;
    } else {
      write_file(filename, buf, skip);
      cout << RES_OK << endl;
    }
  } else {
    cout << string((char *)buf.data(), buf.size()) << endl;
  }
}

/// Build and send a request using the client/server wire format, then
/// decrypt and return the response.  A fresh AES key is generated for each
/// request: the request header (command, AES key, field lengths, username,
/// password) is RSA-encrypted with the server's public key, and any request
/// content is AES-encrypted with the per-request key.  The server replies
/// using the same AES key.
///
/// @param sd       The open socket descriptor for communicating with the server
/// @param pub      The server's public key
/// @param cmd      The command being sent
/// @param user     The username for the request
/// @param password The password for the request
/// @param msg      The request content, to be AES-encrypted
///
/// @return The decrypted response, or an empty vector on error
vector<uint8_t> send_cmd(int sd, EVP_PKEY *pub, const string &cmd,
                         const string &user, const string &password,
                         const vector<uint8_t> &msg) {
  vector<uint8_t> aes_key = create_aes_key();
  if (aes_key.empty())
    return {};

  vector<uint8_t> ablock;
  if (!msg.empty()) {
    ablock = aes_crypt_msg(aes_key, msg, true);
    if (ablock.empty())
      return {};
  }

  vector<uint8_t> rblock;
  add_it(rblock, cmd);
  add_it(rblock, aes_key);
  add_size(rblock, user);
  add_size(rblock, password);
  add_size(rblock, ablock);
  add_it(rblock, user);
  add_it(rblock, password);

  vector<uint8_t> req = rsa_encrypt(pub, rblock);
  if (req.size() != static_cast<size_t>(LEN_RKBLOCK))
    return {};

  add_it(req, ablock);

  if (!send_reliably(sd, req))
    return {};

  vector<uint8_t> res = reliable_get_to_eof(sd);
  if (res.empty())
    return {};

  string raw(res.begin(), res.end());
  if (raw == RES_ERR_CRYPTO || raw == RES_ERR_XMIT || raw == RES_ERR_REQ_FMT)
    return res;

  return aes_crypt_msg(aes_key, res, false);
}

/// Request the server's public key, writing it to a local file once received.
void req_key(int sd, const string &keyfile) {
  vector<uint8_t> req(LEN_RKBLOCK);
  memcpy(req.data(), REQ_KEY.data(), REQ_KEY.size());
  if (!send_reliably(sd, req))
    return;

  vector<uint8_t> res = reliable_get_to_eof(sd);
  if (res.size() != LEN_RSA_PUBKEY) {
    cout << RES_ERR_XMIT << endl;
    return;
  }

  write_file(keyfile, res, 0);
}

/// Register a new user.
void req_reg(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &) {
  auto res = send_cmd(sd, pubkey, REQ_REG, user, pass, empty_vec);
  cout << string((char *)res.data(), res.size()) << endl;
}

/// Ask the server to stop.
void req_bye(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &) {
  auto res = send_cmd(sd, pubkey, REQ_BYE, user, pass, empty_vec);
  cout << string((char *)res.data(), res.size()) << endl;
}

/// Ask the server to persist its data to disk.
void req_sav(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &) {
  auto res = send_cmd(sd, pubkey, REQ_SAV, user, pass, empty_vec);
  cout << string((char *)res.data(), res.size()) << endl;
}

/// Set the calling user's profile content to the contents of a local file.
void req_set(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &setfile) {
  auto data = load_entire_file(setfile);
  vector<uint8_t> block;
  add_size(block, data);
  add_it(block, data);
  auto res = send_cmd(sd, pubkey, REQ_SET, user, pass, block);
  cout << string((char *)res.data(), res.size()) << endl;
}

/// Fetch a user's profile content and save it to `<user>.file.dat`.
void req_get(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &getname) {
  vector<uint8_t> block;
  add_size(block, getname);
  add_it(block, getname);
  auto res = send_cmd(sd, pubkey, REQ_GET, user, pass, block);
  send_result_to_file(res, getname + ".file.dat");
}

/// Fetch a newline-delimited list of all users and save it to a file.
void req_all(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &allfile) {
  auto res = send_cmd(sd, pubkey, REQ_ALL, user, pass, empty_vec);
  send_result_to_file(res, allfile);
}
