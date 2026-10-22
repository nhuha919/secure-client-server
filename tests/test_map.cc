#include <gtest/gtest.h>

#include "../server/sequentialmap.h"

TEST(SequentialMapTest, InsertThenLookupFindsValue) {
  SequentialMap<std::string, int> m(8);
  ASSERT_TRUE(m.insert("a", 1));

  int seen = 0;
  EXPECT_TRUE(m.do_with_readonly("a", [&](const int &v) { seen = v; }));
  EXPECT_EQ(seen, 1);
}

TEST(SequentialMapTest, InsertRejectsDuplicateKey) {
  SequentialMap<std::string, int> m(8);
  ASSERT_TRUE(m.insert("a", 1));
  EXPECT_FALSE(m.insert("a", 2));
}

TEST(SequentialMapTest, UpsertInsertsOnceThenUpdates) {
  SequentialMap<std::string, int> m(8);
  EXPECT_TRUE(m.upsert("a", 1));  // true: this was an insert
  EXPECT_FALSE(m.upsert("a", 2)); // false: this was an update

  int seen = 0;
  m.do_with_readonly("a", [&](const int &v) { seen = v; });
  EXPECT_EQ(seen, 2);
}

TEST(SequentialMapTest, DoWithCanMutateValue) {
  SequentialMap<std::string, int> m(8);
  m.insert("a", 1);
  m.do_with("a", [](int &v) { v += 10; });

  int seen = 0;
  m.do_with_readonly("a", [&](const int &v) { seen = v; });
  EXPECT_EQ(seen, 11);
}

TEST(SequentialMapTest, DoWithOnMissingKeyReturnsFalse) {
  SequentialMap<std::string, int> m(8);
  EXPECT_FALSE(m.do_with("missing", [](int &) {}));
  EXPECT_FALSE(m.do_with_readonly("missing", [](const int &) {}));
}

TEST(SequentialMapTest, RemoveDeletesKeyExactlyOnce) {
  SequentialMap<std::string, int> m(8);
  m.insert("a", 1);
  EXPECT_TRUE(m.remove("a"));
  EXPECT_FALSE(m.remove("a"));
}

TEST(SequentialMapTest, DoAllReadonlyVisitsEveryEntry) {
  SequentialMap<std::string, int> m(8);
  m.insert("a", 1);
  m.insert("b", 2);

  int sum = 0;
  m.do_all_readonly([&](const std::string, const int &v) { sum += v; });
  EXPECT_EQ(sum, 3);
}

TEST(SequentialMapTest, ClearEmptiesMap) {
  SequentialMap<std::string, int> m(8);
  m.insert("a", 1);
  m.clear();
  EXPECT_FALSE(m.do_with_readonly("a", [](const int &) {}));
}
