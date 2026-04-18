#include <catch2/catch_test_macros.hpp>

#include <cstring>

#include "vsecure/metadata.hpp"
#include "vsecure/protocol.hpp"

using namespace vsecure;

TEST_CASE("metadata serialize/parse roundtrip (пустое имя)") {
  FileMetadata m{};
  m.original_size = 42;
  m.unix_timestamp_ms = 1'234'567'890'000ULL;
  std::memset(m.message_id, 0xAB, protocol::kMessageIdLen);
  std::memset(m.sha256_plaintext, 0xCD, protocol::kSha256Len);
  m.filename_utf8 = "";

  const auto w = metadata::serialize(m);
  REQUIRE(w.size() == 8 + 8 + 16 + 32 + 4);

  FileMetadata out{};
  REQUIRE(metadata::parse(w.data(), w.size(), out));
  REQUIRE(out.original_size == m.original_size);
  REQUIRE(out.unix_timestamp_ms == m.unix_timestamp_ms);
  REQUIRE(std::memcmp(out.message_id, m.message_id, protocol::kMessageIdLen) == 0);
  REQUIRE(std::memcmp(out.sha256_plaintext, m.sha256_plaintext, protocol::kSha256Len) == 0);
  REQUIRE(out.filename_utf8 == m.filename_utf8);
}

TEST_CASE("metadata serialize/parse roundtrip (длинное имя)") {
  FileMetadata m{};
  m.original_size = 999;
  m.unix_timestamp_ms = 7;
  std::memset(m.message_id, 1, protocol::kMessageIdLen);
  std::memset(m.sha256_plaintext, 2, protocol::kSha256Len);
  m.filename_utf8.assign(400, 'n');
  m.filename_utf8 += ".mp4";

  const auto w = metadata::serialize(m);
  FileMetadata out{};
  REQUIRE(metadata::parse(w.data(), w.size(), out));
  REQUIRE(out.filename_utf8 == m.filename_utf8);
}

TEST_CASE("metadata parse: слишком короткий буфер") {
  unsigned char buf[16]{};
  FileMetadata out{};
  REQUIRE_FALSE(metadata::parse(buf, sizeof(buf), out));
}

TEST_CASE("metadata parse: filename_len выходит за границу") {
  FileMetadata m{};
  m.filename_utf8 = "x";
  const auto w = metadata::serialize(m);
  FileMetadata out{};
  REQUIRE_FALSE(metadata::parse(w.data(), w.size() - 1, out));
}
