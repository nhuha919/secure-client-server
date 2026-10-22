#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sys/stat.h>

#include "constants.h"
#include "contextmanager.h"
#include "crypto.h"
#include "err.h"

using namespace std;

/// Load an RSA public key from the given filename
EVP_PKEY *load_pub(const char *filename) {
  FILE *pub = fopen(filename, "r");
  if (pub == nullptr)
    return err<EVP_PKEY *>(nullptr, "Error opening public key file");
  ContextManager cf([&]() { fclose(pub); });
  EVP_PKEY *rsa = PEM_read_PUBKEY(pub, NULL, NULL, NULL);
  if (rsa == nullptr)
    return err<EVP_PKEY *>(nullptr, "Error reading public key file");
  return rsa;
}

/// Load an RSA private key from the given filename
EVP_PKEY *load_pri(const char *filename) {
  FILE *pri = fopen(filename, "r");
  if (pri == nullptr)
    return err<EVP_PKEY *>(nullptr, "Error opening private key file");
  ContextManager cf([&]() { fclose(pri); });
  EVP_PKEY *rsa = PEM_read_PrivateKey(pri, NULL, NULL, NULL);
  if (rsa == nullptr)
    return err<EVP_PKEY *>(nullptr, "Error reading private key file");
  return rsa;
}

/// Generate an RSA key pair and save its public and private parts to files
bool generate_rsa_key_files(const string &pub, const string &pri) {
  cout << "Generating RSA keys as (" << pub << ", " << pri << ")\n";

  EVP_PKEY *rsa = EVP_RSA_gen(RSA_KEYSIZE);
  if (rsa == nullptr)
    return err(false, "Error in EVP_RSA_gen()");
  ContextManager key([&]() { EVP_PKEY_free(rsa); });

  FILE *pubfile = fopen(pub.c_str(), "w");
  if (pubfile == nullptr)
    return err(false, "Error opening public key file for output");
  ContextManager pubclose([&]() { fclose(pubfile); });

  FILE *prifile = fopen(pri.c_str(), "w");
  if (prifile == nullptr)
    return err(false, "Error opening private key file for output");
  ContextManager priclose([&]() { fclose(prifile); });

  if (PEM_write_PUBKEY(pubfile, rsa) != 1)
    return err(false, "Error writing public key");
  else if (PEM_write_PrivateKey(prifile, rsa, 0, 0, 0, 0, 0) != 1)
    return err(false, "Error writing private key");
  return true;
}

/// Run the AES symmetric encryption/decryption algorithm on a vector
vector<uint8_t> aes_crypt_msg(vector<uint8_t> key, const vector<uint8_t> &msg,
                               bool type) {
  return aes_crypt_msg(key, msg.data(), msg.size(), type);
}

/// Run the AES symmetric encryption/decryption algorithm on a string
vector<uint8_t> aes_crypt_msg(vector<uint8_t> key, const string &msg,
                               bool type) {
  return aes_crypt_msg(key, (unsigned char *)msg.c_str(), msg.length(), type);
}

/// Create an AES key.  A key has two parts: the key itself, and the
/// initialization vector.  Both are random bits.
vector<uint8_t> create_aes_key() {
  vector<uint8_t> key(AES_KEYSIZE + AES_IVSIZE);
  if (!RAND_bytes(key.data(), AES_KEYSIZE) ||
      !RAND_bytes(key.data() + AES_KEYSIZE, AES_IVSIZE))
    return err<vector<uint8_t>>({}, "Error in RAND_bytes()");
  return key;
}

/// Create an AES context for doing a single encryption or decryption
EVP_CIPHER_CTX *create_aes_context(const vector<uint8_t> &key, bool encrypt) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr)
    return err<EVP_CIPHER_CTX *>(nullptr,
                                  "Error: OpenSSL couldn't create context: ",
                                  ERR_error_string(ERR_get_error(), 0));
  ContextManager c([&]() { EVP_CIPHER_CTX_cleanup(ctx); });

  if (!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), 0, 0, 0, encrypt))
    return err<EVP_CIPHER_CTX *>(
        nullptr, "Error: OpenSSL couldn't initialize context: ",
        ERR_error_string(ERR_get_error(), 0));
  if ((EVP_CIPHER_CTX_key_length(ctx) != AES_KEYSIZE) ||
      (EVP_CIPHER_CTX_iv_length(ctx) != AES_IVSIZE))
    return err<EVP_CIPHER_CTX *>(
        nullptr, "Error: OpenSSL couldn't initialize context: ",
        ERR_error_string(ERR_get_error(), 0));

  if (!EVP_CipherInit_ex(ctx, nullptr, nullptr, key.data(),
                         key.data() + AES_KEYSIZE, encrypt))
    return err<EVP_CIPHER_CTX *>(nullptr,
                                  "Error: OpenSSL couldn't re-init context: ",
                                  ERR_error_string(ERR_get_error(), 0));
  c.disable();
  return ctx;
}

/// Reset an existing AES context so it can be reused
bool reset_aes_context(EVP_CIPHER_CTX *ctx, vector<uint8_t> &key,
                        bool encrypt) {
  if (!EVP_CipherInit_ex(ctx, nullptr, nullptr, key.data(),
                         key.data() + AES_KEYSIZE, encrypt)) {
    EVP_CIPHER_CTX_cleanup(ctx);
    return err(false, "Error: OpenSSL couldn't re-init context: ",
               ERR_error_string(ERR_get_error(), 0));
  }
  return true;
}

/// Reclaim the memory associated with an AES context
void reclaim_aes_context(EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); }

/// If `basename.pri`/`basename.pub` exist, load the private key.  If neither
/// exists, generate a fresh key pair first.
EVP_PKEY *init_RSA(const string &basename) {
  string pubfile = basename + ".pub", prifile = basename + ".pri";

  struct stat stat_buf;
  bool pub_exists = (stat(pubfile.c_str(), &stat_buf) == 0);
  bool pri_exists = (stat(prifile.c_str(), &stat_buf) == 0);

  if (!pub_exists && !pri_exists)
    generate_rsa_key_files(pubfile, prifile);
  else if (pub_exists && !pri_exists)
    return err<EVP_PKEY *>(nullptr, "Error: cannot find ", basename.c_str(),
                           ".pri");
  else if (!pub_exists && pri_exists)
    return err<EVP_PKEY *>(nullptr, "Error: cannot find ", basename.c_str(),
                           ".pub");
  return load_pri(prifile.c_str());
}

/// Run the AES symmetric encryption/decryption algorithm on a buffer of bytes
vector<uint8_t> aes_crypt_msg(vector<uint8_t> key, const unsigned char *start,
                               int count, bool type) {
  EVP_CIPHER_CTX *ctx = create_aes_context(key, type);
  if (ctx == nullptr)
    return {};
  ContextManager c([&]() { reclaim_aes_context(ctx); });

  int block = EVP_CIPHER_CTX_block_size(ctx);
  vector<uint8_t> out(count + block);
  int out_len = 0, final_len = 0;

  if (!EVP_CipherUpdate(ctx, out.data(), &out_len, start, count))
    return {};
  if (!EVP_CipherFinal_ex(ctx, out.data() + out_len, &final_len))
    return {};

  out.resize(out_len + final_len);
  return out;
}

/// Run the RSA asymmetric encryption algorithm on a buffer of bytes
vector<uint8_t> rsa_encrypt(EVP_PKEY *pub, vector<uint8_t> block) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, nullptr);
  if (ctx == nullptr)
    return {};
  ContextManager c([&]() { EVP_PKEY_CTX_free(ctx); });

  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    return {};

  size_t out_len = 0;
  if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, block.data(), block.size()) <= 0)
    return {};

  vector<uint8_t> out(out_len);
  if (EVP_PKEY_encrypt(ctx, out.data(), &out_len, block.data(), block.size()) <=
      0)
    return {};

  out.resize(out_len);
  return out;
}

/// Run the RSA asymmetric decryption algorithm on a buffer of bytes
vector<uint8_t> rsa_decrypt(EVP_PKEY *pri, vector<uint8_t> block) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pri, nullptr);
  if (ctx == nullptr)
    return {};
  ContextManager c([&]() { EVP_PKEY_CTX_free(ctx); });

  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    return {};

  size_t out_len = 0;
  if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, block.data(), block.size()) <= 0)
    return {};

  vector<uint8_t> out(out_len);
  if (EVP_PKEY_decrypt(ctx, out.data(), &out_len, block.data(), block.size()) <=
      0)
    return {};

  out.resize(out_len);
  return out;
}
