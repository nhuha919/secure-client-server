#include <cstring>

#include "../common/constants.h"
#include "../common/crypto.h"
#include "../common/net.h"

#include "responses.h"

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

/// Concatenate a message and a content blob into the wire format clients
/// expect: msg . len(content) . content
///
/// @param msg     The message to send to the client
/// @param content The content to send to the client
///
/// @return A buffer with the correct concatenation of msg and content
vector<uint8_t> build_res(const string &msg, const vector<uint8_t> &content) {
  vector<uint8_t> buf;
  add_it(buf, msg);
  add_size(buf, content);
  add_it(buf, content);
  return buf;
}

/// Reply to an ALL request with a newline-delimited list of all usernames.
bool handle_all(int sd, Storage *storage, vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &req) {
  Storage::result_t res = storage->get_all_users(u, p);
  if (res.succeeded) {
    vector<uint8_t> encrypted_res =
        aes_crypt_msg(aeskey, build_res(res.msg, res.data), true);
    send_reliably(sd, encrypted_res);
  } else {
    send_reliably(sd, aes_crypt_msg(aeskey, res.msg, true));
  }
  return false;
}

/// Reply to a SET request by storing new profile content for the user.
bool handle_set(int sd, Storage *storage, vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &req) {
  if (req.size() < sizeof(uint32_t)) {
    send_reliably(sd, aes_crypt_msg(aeskey, RES_ERR_REQ_FMT, true));
    return false;
  }

  auto it = req.begin();
  uint32_t lenF = extract_size(it);

  if (lenF > LEN_PROFILE_FILE || req.size() != sizeof(uint32_t) + lenF) {
    send_reliably(sd, aes_crypt_msg(aeskey, RES_ERR_REQ_FMT, true));
    return false;
  }

  vector<uint8_t> f = extract_vec(it, lenF);

  Storage::result_t res = storage->set_user_data(u, p, f);
  send_reliably(sd, aes_crypt_msg(aeskey, res.msg, true));
  return false;
}

/// Reply to a GET request with another user's profile content.
bool handle_get(int sd, Storage *storage, vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &req) {
  if (req.size() < sizeof(uint32_t)) {
    send_reliably(sd, aes_crypt_msg(aeskey, RES_ERR_REQ_FMT, true));
    return false;
  }

  auto it = req.begin();
  uint32_t lenW = extract_size(it);
  if (lenW > LEN_UNAME || req.size() != sizeof(uint32_t) + lenW) {
    send_reliably(sd, aes_crypt_msg(aeskey, RES_ERR_REQ_FMT, true));
    return false;
  }

  string w = extract_string(it, lenW);

  Storage::result_t res = storage->get_user_data(u, p, w);
  if (res.succeeded) {
    vector<uint8_t> encrypted_res =
        aes_crypt_msg(aeskey, build_res(res.msg, res.data), true);
    send_reliably(sd, encrypted_res);
  } else {
    send_reliably(sd, aes_crypt_msg(aeskey, res.msg, true));
  }
  return false;
}

/// Reply to a REG request by trying to create a new user.
bool handle_reg(int sd, Storage *storage, vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &req) {
  Storage::result_t res = storage->add_user(u, p);
  send_reliably(sd, aes_crypt_msg(aeskey, res.msg, true));
  return false;
}

/// Reply to a KEY request by sending the server's public key file contents.
bool handle_key(int sd, const vector<uint8_t> &pubfile) {
  send_reliably(sd, pubfile);
  return false;
}

/// Reply to a BYE request, halting the server if the user authenticates.
bool handle_bye(int sd, Storage *storage, vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &req) {
  Storage::result_t res = storage->auth(u, p);
  send_reliably(sd, aes_crypt_msg(aeskey, res.msg, true));
  return res.succeeded;
}

/// Reply to a SAV request by persisting storage to disk, if the user
/// authenticates.
bool handle_sav(int sd, Storage *storage, vector<uint8_t> aeskey,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &req) {
  Storage::result_t auth_res = storage->auth(u, p);
  if (!auth_res.succeeded) {
    send_reliably(sd, aes_crypt_msg(aeskey, auth_res.msg, true));
    return false;
  }

  Storage::result_t res = storage->save_file();
  send_reliably(sd, aes_crypt_msg(aeskey, res.msg, true));
  return false;
}
