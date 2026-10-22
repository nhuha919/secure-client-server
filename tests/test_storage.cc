#include <cstdio>

#include <gtest/gtest.h>

#include "../server/storage.h"

/// Gives every test its own scratch file (named after the test), and cleans
/// up before and after in case a previous run left something behind.
class StorageTest : public ::testing::Test {
protected:
  std::string path;

  void SetUp() override {
    const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
    path = std::string("/tmp/sds_test_storage_") + info->name() + ".bin";
    remove(path.c_str());
    remove((path + ".tmp").c_str());
  }

  void TearDown() override {
    remove(path.c_str());
    remove((path + ".tmp").c_str());
  }
};

TEST_F(StorageTest, AddUserRejectsDuplicateUsername) {
  Storage *s = storage_factory(path, 8);
  EXPECT_TRUE(s->add_user("alice", "pw1").succeeded);
  EXPECT_FALSE(s->add_user("alice", "pw2").succeeded);
  delete s;
}

TEST_F(StorageTest, AuthSucceedsOnlyWithRightPassword) {
  Storage *s = storage_factory(path, 8);
  s->add_user("bob", "secret");
  EXPECT_TRUE(s->auth("bob", "secret").succeeded);
  EXPECT_FALSE(s->auth("bob", "wrong").succeeded);
  EXPECT_FALSE(s->auth("nobody", "whatever").succeeded);
  delete s;
}

TEST_F(StorageTest, SetThenGetUserDataRoundTrips) {
  Storage *s = storage_factory(path, 8);
  s->add_user("carol", "pw");
  std::vector<uint8_t> content = {1, 2, 3, 4};

  EXPECT_TRUE(s->set_user_data("carol", "pw", content).succeeded);
  auto res = s->get_user_data("carol", "pw", "carol");
  ASSERT_TRUE(res.succeeded);
  EXPECT_EQ(res.data, content);
  delete s;
}

TEST_F(StorageTest, SetUserDataRequiresRightPassword) {
  Storage *s = storage_factory(path, 8);
  s->add_user("dave", "pw");
  EXPECT_FALSE(s->set_user_data("dave", "wrong", {1, 2, 3}).succeeded);
  delete s;
}

TEST_F(StorageTest, GetUserDataFailsWhenNoContentYet) {
  Storage *s = storage_factory(path, 8);
  s->add_user("erin", "pw");
  EXPECT_FALSE(s->get_user_data("erin", "pw", "erin").succeeded);
  delete s;
}

TEST_F(StorageTest, GetUserDataFailsForUnknownTargetUser) {
  Storage *s = storage_factory(path, 8);
  s->add_user("frank", "pw");
  EXPECT_FALSE(s->get_user_data("frank", "pw", "nosuchuser").succeeded);
  delete s;
}

TEST_F(StorageTest, AnyAuthenticatedUserCanReadAnotherUsersData) {
  Storage *s = storage_factory(path, 8);
  s->add_user("grace", "pw1");
  s->add_user("heidi", "pw2");
  s->set_user_data("grace", "pw1", {9, 9, 9});

  auto res = s->get_user_data("heidi", "pw2", "grace");
  ASSERT_TRUE(res.succeeded);
  EXPECT_EQ(res.data, std::vector<uint8_t>({9, 9, 9}));
  delete s;
}

TEST_F(StorageTest, GetAllUsersListsEveryRegisteredName) {
  Storage *s = storage_factory(path, 8);
  s->add_user("ivan", "pw");
  s->add_user("judy", "pw");

  auto res = s->get_all_users("ivan", "pw");
  ASSERT_TRUE(res.succeeded);
  std::string list(res.data.begin(), res.data.end());
  EXPECT_NE(list.find("ivan"), std::string::npos);
  EXPECT_NE(list.find("judy"), std::string::npos);
  delete s;
}

TEST_F(StorageTest, LoadFileOnMissingFileIsNotAnError) {
  Storage *s = storage_factory(path, 8);
  EXPECT_TRUE(s->load_file().succeeded);
  delete s;
}

TEST_F(StorageTest, SaveFileThenLoadFileRestoresEverything) {
  {
    Storage *s = storage_factory(path, 8);
    s->add_user("mallory", "pw");
    s->set_user_data("mallory", "pw", {4, 5, 6});
    ASSERT_TRUE(s->save_file().succeeded);
    delete s;
  }
  {
    Storage *s = storage_factory(path, 8);
    ASSERT_TRUE(s->load_file().succeeded);
    EXPECT_TRUE(s->auth("mallory", "pw").succeeded);

    auto res = s->get_user_data("mallory", "pw", "mallory");
    ASSERT_TRUE(res.succeeded);
    EXPECT_EQ(res.data, std::vector<uint8_t>({4, 5, 6}));
    delete s;
  }
}
