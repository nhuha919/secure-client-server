#include <cstdio>

#include "../common/file.h"
#include "test_framework.h"

TEST(file_exists_is_false_for_a_missing_file) {
  CHECK(!file_exists("/tmp/sds_test_definitely_missing_file.bin"));
}

TEST(write_file_then_load_entire_file_round_trips) {
  std::string path = "/tmp/sds_test_write_load.bin";
  std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};

  CHECK(write_file(path, data, 0));
  CHECK(file_exists(path));
  CHECK_EQ(load_entire_file(path), data);

  remove(path.c_str());
}

TEST(write_file_honors_skip_offset) {
  std::string path = "/tmp/sds_test_write_skip.bin";
  std::vector<uint8_t> data = {0, 0, 0, 0, 'a', 'b', 'c'};
  std::vector<uint8_t> expected = {'a', 'b', 'c'};

  CHECK(write_file(path, data, 4));
  CHECK_EQ(load_entire_file(path), expected);

  remove(path.c_str());
}

TEST(load_entire_file_returns_empty_for_missing_file) {
  CHECK(load_entire_file("/tmp/sds_test_definitely_missing_file.bin").empty());
}
