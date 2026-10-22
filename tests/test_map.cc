#include "../server/sequentialmap.h"
#include "test_framework.h"

TEST(map_insert_then_lookup_finds_the_value) {
  SequentialMap<std::string, int> m(8);
  CHECK(m.insert("a", 1));

  int seen = 0;
  CHECK(m.do_with_readonly("a", [&](const int &v) { seen = v; }));
  CHECK_EQ(seen, 1);
}

TEST(map_insert_rejects_a_duplicate_key) {
  SequentialMap<std::string, int> m(8);
  CHECK(m.insert("a", 1));
  CHECK(!m.insert("a", 2));
}

TEST(map_upsert_inserts_once_then_updates) {
  SequentialMap<std::string, int> m(8);
  CHECK(m.upsert("a", 1));  // true: this was an insert
  CHECK(!m.upsert("a", 2)); // false: this was an update

  int seen = 0;
  m.do_with_readonly("a", [&](const int &v) { seen = v; });
  CHECK_EQ(seen, 2);
}

TEST(map_do_with_can_mutate_the_value) {
  SequentialMap<std::string, int> m(8);
  m.insert("a", 1);
  m.do_with("a", [](int &v) { v += 10; });

  int seen = 0;
  m.do_with_readonly("a", [&](const int &v) { seen = v; });
  CHECK_EQ(seen, 11);
}

TEST(map_do_with_on_missing_key_returns_false) {
  SequentialMap<std::string, int> m(8);
  CHECK(!m.do_with("missing", [](int &) {}));
  CHECK(!m.do_with_readonly("missing", [](const int &) {}));
}

TEST(map_remove_deletes_the_key_exactly_once) {
  SequentialMap<std::string, int> m(8);
  m.insert("a", 1);
  CHECK(m.remove("a"));
  CHECK(!m.remove("a"));
}

TEST(map_do_all_readonly_visits_every_entry) {
  SequentialMap<std::string, int> m(8);
  m.insert("a", 1);
  m.insert("b", 2);

  int sum = 0;
  m.do_all_readonly([&](const std::string, const int &v) { sum += v; });
  CHECK_EQ(sum, 3);
}

TEST(map_clear_empties_the_map) {
  SequentialMap<std::string, int> m(8);
  m.insert("a", 1);
  m.clear();
  CHECK(!m.do_with_readonly("a", [](const int &) {}));
}
