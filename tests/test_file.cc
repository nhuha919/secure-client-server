#include <cstdio>

#include <gtest/gtest.h>

#include "../common/file.h"

TEST(FileTest, FileExistsIsFalseForMissingFile) {
  EXPECT_FALSE(file_exists("/tmp/sds_test_definitely_missing_file.bin"));
}

TEST(FileTest, WriteThenLoadEntireFileRoundTrips) {
  std::string path = "/tmp/sds_test_write_load.bin";
  std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};

  ASSERT_TRUE(write_file(path, data, 0));
  EXPECT_TRUE(file_exists(path));
  EXPECT_EQ(load_entire_file(path), data);

  remove(path.c_str());
}

TEST(FileTest, WriteFileHonorsSkipOffset) {
  std::string path = "/tmp/sds_test_write_skip.bin";
  std::vector<uint8_t> data = {0, 0, 0, 0, 'a', 'b', 'c'};
  std::vector<uint8_t> expected = {'a', 'b', 'c'};

  ASSERT_TRUE(write_file(path, data, 4));
  EXPECT_EQ(load_entire_file(path), expected);

  remove(path.c_str());
}

TEST(FileTest, LoadEntireFileReturnsEmptyForMissingFile) {
  EXPECT_TRUE(load_entire_file("/tmp/sds_test_definitely_missing_file.bin").empty());
}
