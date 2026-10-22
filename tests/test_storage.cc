#include <cstdio>

#include "../server/storage.h"
#include "test_framework.h"

TEST(storage_add_user_rejects_a_duplicate_username) {
  Storage *s = storage_factory("/tmp/sds_test_storage_dup.bin", 8);
  CHECK(s->add_user("alice", "pw1").succeeded);
  CHECK(!s->add_user("alice", "pw2").succeeded);
  delete s;
}

TEST(storage_auth_succeeds_only_with_the_right_password) {
  Storage *s = storage_factory("/tmp/sds_test_storage_auth.bin", 8);
  s->add_user("bob", "secret");
  CHECK(s->auth("bob", "secret").succeeded);
  CHECK(!s->auth("bob", "wrong").succeeded);
  CHECK(!s->auth("nobody", "whatever").succeeded);
  delete s;
}

TEST(storage_set_then_get_user_data_round_trips) {
  Storage *s = storage_factory("/tmp/sds_test_storage_setget.bin", 8);
  s->add_user("carol", "pw");
  std::vector<uint8_t> content = {1, 2, 3, 4};

  CHECK(s->set_user_data("carol", "pw", content).succeeded);
  auto res = s->get_user_data("carol", "pw", "carol");
  CHECK(res.succeeded);
  CHECK_EQ(res.data, content);
  delete s;
}

TEST(storage_set_user_data_requires_the_right_password) {
  Storage *s = storage_factory("/tmp/sds_test_storage_setauth.bin", 8);
  s->add_user("dave", "pw");
  CHECK(!s->set_user_data("dave", "wrong", {1, 2, 3}).succeeded);
  delete s;
}

TEST(storage_get_user_data_fails_when_there_is_no_content_yet) {
  Storage *s = storage_factory("/tmp/sds_test_storage_nodata.bin", 8);
  s->add_user("erin", "pw");
  CHECK(!s->get_user_data("erin", "pw", "erin").succeeded);
  delete s;
}

TEST(storage_get_user_data_fails_for_an_unknown_target_user) {
  Storage *s = storage_factory("/tmp/sds_test_storage_nouser.bin", 8);
  s->add_user("frank", "pw");
  CHECK(!s->get_user_data("frank", "pw", "nosuchuser").succeeded);
  delete s;
}

TEST(storage_any_authenticated_user_can_read_another_users_data) {
  Storage *s = storage_factory("/tmp/sds_test_storage_crossread.bin", 8);
  s->add_user("grace", "pw1");
  s->add_user("heidi", "pw2");
  s->set_user_data("grace", "pw1", {9, 9, 9});

  auto res = s->get_user_data("heidi", "pw2", "grace");
  CHECK(res.succeeded);
  CHECK_EQ(res.data, std::vector<uint8_t>({9, 9, 9}));
  delete s;
}

TEST(storage_get_all_users_lists_every_registered_name) {
  Storage *s = storage_factory("/tmp/sds_test_storage_listall.bin", 8);
  s->add_user("ivan", "pw");
  s->add_user("judy", "pw");

  auto res = s->get_all_users("ivan", "pw");
  CHECK(res.succeeded);
  std::string list(res.data.begin(), res.data.end());
  CHECK(list.find("ivan") != std::string::npos);
  CHECK(list.find("judy") != std::string::npos);
  delete s;
}

TEST(storage_load_file_on_a_missing_file_is_not_an_error) {
  std::string path = "/tmp/sds_test_storage_missing.bin";
  remove(path.c_str());

  Storage *s = storage_factory(path, 8);
  CHECK(s->load_file().succeeded);
  delete s;
}

TEST(storage_save_file_then_load_file_restores_everything) {
  std::string path = "/tmp/sds_test_storage_persist.bin";
  remove(path.c_str());
  remove((path + ".tmp").c_str());

  {
    Storage *s = storage_factory(path, 8);
    s->add_user("mallory", "pw");
    s->set_user_data("mallory", "pw", {4, 5, 6});
    CHECK(s->save_file().succeeded);
    delete s;
  }
  {
    Storage *s = storage_factory(path, 8);
    CHECK(s->load_file().succeeded);
    CHECK(s->auth("mallory", "pw").succeeded);

    auto res = s->get_user_data("mallory", "pw", "mallory");
    CHECK(res.succeeded);
    CHECK_EQ(res.data, std::vector<uint8_t>({4, 5, 6}));
    delete s;
  }

  remove(path.c_str());
}
