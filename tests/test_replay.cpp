#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>
#include <unistd.h>

#include "vsecure/replay.hpp"

namespace fs = std::filesystem;

TEST_CASE("timestamp_ok: внутри окна и на границе") {
  using vsecure::replay::MessageIdStore;
  using vsecure::replay::kTimestampWindowMs;

  REQUIRE(MessageIdStore::timestamp_ok(1'000'000ULL, 1'000'000ULL));
  REQUIRE(MessageIdStore::timestamp_ok(1'000'000ULL, 1'000'000ULL + kTimestampWindowMs));
  REQUIRE(MessageIdStore::timestamp_ok(1'000'000ULL + kTimestampWindowMs, 1'000'000ULL));
}

TEST_CASE("timestamp_ok: вне окна (актуальность сообщения)") {
  using vsecure::replay::MessageIdStore;
  using vsecure::replay::kTimestampWindowMs;

  REQUIRE_FALSE(MessageIdStore::timestamp_ok(1'000'000ULL, 1'000'000ULL + kTimestampWindowMs + 1));
  REQUIRE_FALSE(MessageIdStore::timestamp_ok(1'000'000ULL + kTimestampWindowMs + 1, 1'000'000ULL));
}

TEST_CASE("MessageIdStore: уникальность и персистентность") {
  const fs::path tmp =
      fs::temp_directory_path() / ("vst_replay_" + std::to_string(static_cast<long>(::getpid())));
  fs::create_directories(tmp);
  const std::string seen = (tmp / "seen.txt").string();

  unsigned char id[16]{};
  id[0] = 0x42;
  id[15] = 0x7F;

  {
    vsecure::replay::MessageIdStore st(seen);
    REQUIRE_FALSE(st.is_replay(id));
    st.commit(id);
  }
  {
    vsecure::replay::MessageIdStore st2(seen);
    REQUIRE(st2.is_replay(id));
  }

  std::error_code ec;
  fs::remove_all(tmp, ec);
}
