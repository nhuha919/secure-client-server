#pragma once

#include <openssl/pem.h>
#include <string>
#include <vector>

/// Load an RSA public key from the given filename
///
/// @param filename The name of the file that has the public key in it
///
/// @return An RSA context for encrypting with the provided public key, or
///         nullptr on error
EVP_PKEY *load_pub(const char *filename);

/// Run the AES symmetric encryption/decryption algorithm on a buffer of
/// bytes.
///
/// @param key   The session key (and IV) to use for the operation
/// @param start A pointer to the first byte to encrypt/decrypt
/// @param count The number of bytes in the buffer
/// @param type  true to encrypt, false to decrypt
///
/// @return A vector with the encrypted or decrypted result, or an empty
///         vector if there was an error
std::vector<uint8_t> aes_crypt_msg(std::vector<uint8_t> key,
                                    const unsigned char *start, int count,
                                    bool type);

/// Run the AES symmetric encryption/decryption algorithm on a vector.
///
/// @param key  The session key (and IV) to use for the operation
/// @param msg  A vector to encrypt/decrypt
/// @param type true to encrypt, false to decrypt
///
/// @return A vector with the encrypted or decrypted result, or an empty
///         vector if there was an error
std::vector<uint8_t> aes_crypt_msg(std::vector<uint8_t> key,
                                    const std::vector<uint8_t> &msg,
                                    bool type);

/// Run the AES symmetric encryption/decryption algorithm on a string.
///
/// @param key  The session key (and IV) to use for the operation
/// @param msg  A string to encrypt/decrypt
/// @param type true to encrypt, false to decrypt
///
/// @return A vector with the encrypted or decrypted result, or an empty
///         vector if there was an error
std::vector<uint8_t> aes_crypt_msg(std::vector<uint8_t> key,
                                    const std::string &msg, bool type);

/// Create an AES key.  A key has two parts: the key itself, and the
/// initialization vector.  Both are random bits; we produce them as a single
/// buffer that callers can slice as needed.
///
/// @return A vector holding the key and iv bits, or an empty vector on error
std::vector<uint8_t> create_aes_key();

/// Create an AES context for doing a single encryption or decryption.  The
/// context must be reset before it can be reused.
///
/// @param key     A vector holding the bits of the key and iv
/// @param encrypt true to encrypt, false to decrypt
///
/// @return An AES context, or nullptr on error
EVP_CIPHER_CTX *create_aes_context(const std::vector<uint8_t> &key,
                                    bool encrypt);

/// Reset an existing AES context so it can be reused for another
/// encryption/decryption
///
/// @param ctx     The AES context to reset
/// @param key     A vector holding the bits of the key and iv
/// @param encrypt true to create an encryption context, false to create a
///                decryption context
///
/// @return false on error, true if the context is reset and ready to use again
bool reset_aes_context(EVP_CIPHER_CTX *ctx, std::vector<uint8_t> &key,
                        bool encrypt);

/// Reclaim the memory associated with an AES context
///
/// @param ctx The context to reclaim
void reclaim_aes_context(EVP_CIPHER_CTX *ctx);

/// If `basename.pri` and `basename.pub` both exist, load and return the
/// private key.  If only one exists, that's an error.  If neither exists,
/// generate a fresh key pair first.
///
/// @param basename The basename of the .pri and .pub files for RSA
///
/// @return The private key, or nullptr on error
EVP_PKEY *init_RSA(const std::string &basename);

/// Run the RSA asymmetric decryption algorithm on a buffer of bytes using the
/// private key
///
/// @param pri   The private key for this operation
/// @param block A buffer of bytes to decrypt
///
/// @return A vector with the decrypted result, or an empty vector if there
///         was an error
std::vector<uint8_t> rsa_decrypt(EVP_PKEY *pri, std::vector<uint8_t> block);

/// Run the RSA asymmetric encryption algorithm on a buffer of bytes using the
/// public key
///
/// @param pub   The public key for this operation
/// @param block A buffer of bytes to encrypt
///
/// @return A vector with the encrypted result, or an empty vector if there
///         was an error
std::vector<uint8_t> rsa_encrypt(EVP_PKEY *pub, std::vector<uint8_t> block);
