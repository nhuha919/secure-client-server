#include <algorithm>
#include <cstdio>

#include <gtest/gtest.h>

#include "../common/constants.h"
#include "../common/crypto.h"
#include "../common/file.h"

TEST(CryptoTest, CreateAesKeyHasExpectedLength) {
  auto key = create_aes_key();
  EXPECT_EQ(key.size(), static_cast<size_t>(AES_KEYSIZE + AES_IVSIZE));
}

TEST(CryptoTest, AesCryptMsgRoundTripsAString) {
  auto key = create_aes_key();
  std::string msg = "the quick brown fox";

  auto ciphertext = aes_crypt_msg(key, msg, true);
  ASSERT_FALSE(ciphertext.empty());

  auto plaintext = aes_crypt_msg(key, ciphertext, false);
  EXPECT_EQ(std::string(plaintext.begin(), plaintext.end()), msg);
}

TEST(CryptoTest, AesCryptMsgRoundTripsAVector) {
  auto key = create_aes_key();
  std::vector<uint8_t> msg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  auto ciphertext = aes_crypt_msg(key, msg, true);
  auto plaintext = aes_crypt_msg(key, ciphertext, false);
  EXPECT_EQ(plaintext, msg);
}

TEST(CryptoTest, AesCryptMsgWithWrongKeyDoesNotRecoverPlaintext) {
  auto key = create_aes_key();
  auto wrong_key = create_aes_key();
  std::string msg = "a message that is long enough to span a full AES block";

  auto ciphertext = aes_crypt_msg(key, msg, true);
  auto plaintext = aes_crypt_msg(wrong_key, ciphertext, false);

  // PKCS#7 unpadding after decrypting with the wrong key will usually (but
  // isn't guaranteed to) fail outright; either way the recovered bytes must
  // not equal the original message.
  bool matches = plaintext.size() == msg.size() &&
                 std::equal(plaintext.begin(), plaintext.end(), msg.begin());
  EXPECT_FALSE(matches);
}

TEST(CryptoTest, RsaEncryptDecryptRoundTripsABlock) {
  std::string base = "/tmp/sds_test_rsa_key";
  remove((base + ".pub").c_str());
  remove((base + ".pri").c_str());

  EVP_PKEY *pri = init_RSA(base);
  ASSERT_NE(pri, nullptr);
  EVP_PKEY *pub = load_pub((base + ".pub").c_str());
  ASSERT_NE(pub, nullptr);

  std::vector<uint8_t> msg(LEN_RBLOCK_CONTENT, 0);
  std::string tag = "hello-rsa";
  std::copy(tag.begin(), tag.end(), msg.begin());

  auto ciphertext = rsa_encrypt(pub, msg);
  ASSERT_EQ(ciphertext.size(), static_cast<size_t>(LEN_RKBLOCK));

  auto plaintext = rsa_decrypt(pri, ciphertext);
  EXPECT_EQ(plaintext, msg);

  EVP_PKEY_free(pri);
  EVP_PKEY_free(pub);
  remove((base + ".pub").c_str());
  remove((base + ".pri").c_str());
}

TEST(CryptoTest, InitRsaReusesExistingKeyPair) {
  std::string base = "/tmp/sds_test_rsa_key_reuse";
  remove((base + ".pub").c_str());
  remove((base + ".pri").c_str());

  EVP_PKEY *first = init_RSA(base);
  ASSERT_NE(first, nullptr);
  auto pub_bytes_first = load_entire_file(base + ".pub");

  EVP_PKEY *second = init_RSA(base);
  ASSERT_NE(second, nullptr);
  auto pub_bytes_second = load_entire_file(base + ".pub");

  EXPECT_EQ(pub_bytes_first, pub_bytes_second);

  EVP_PKEY_free(first);
  EVP_PKEY_free(second);
  remove((base + ".pub").c_str());
  remove((base + ".pri").c_str());
}
