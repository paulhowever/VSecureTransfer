#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <vector>

#include "vsecure/metadata.hpp"
#include "vsecure/packet.hpp"
#include "vsecure/protocol.hpp"

using namespace vsecure;

static TransferPacket minimal_packet() {
  TransferPacket p{};
  p.meta.original_size = 10;
  p.meta.unix_timestamp_ms = 100;
  std::memset(p.meta.message_id, 3, protocol::kMessageIdLen);
  std::memset(p.meta.sha256_plaintext, 4, protocol::kSha256Len);
  p.meta.filename_utf8 = "clip.mkv";
  p.iv.assign(protocol::kGcmIvLen, 0x11);
  p.wrapped_key.assign(32, 0x22);
  p.signature.assign(64, 0x33);
  p.ciphertext.assign(protocol::kGcmTagLen, 0x44);
  return p;
}

TEST_CASE("packet encode/decode roundtrip") {
  const auto p0 = minimal_packet();
  std::vector<unsigned char> wire;
  REQUIRE(packet::encode_file_transfer(p0, wire));

  TransferPacket p1{};
  REQUIRE(packet::decode_file_transfer(wire.data(), wire.size(), p1));
  REQUIRE(p1.meta.original_size == p0.meta.original_size);
  REQUIRE(p1.meta.filename_utf8 == p0.meta.filename_utf8);
  REQUIRE(p1.iv == p0.iv);
  REQUIRE(p1.wrapped_key == p0.wrapped_key);
  REQUIRE(p1.signature == p0.signature);
  REQUIRE(p1.ciphertext == p0.ciphertext);
}

TEST_CASE("packet decode: неверный magic") {
  auto wire = [] {
    const auto p = minimal_packet();
    std::vector<unsigned char> w;
    packet::encode_file_transfer(p, w);
    return w;
  }();
  wire[0] = 'X';
  TransferPacket out{};
  REQUIRE_FALSE(packet::decode_file_transfer(wire.data(), wire.size(), out));
}

TEST_CASE("packet decode: обрезанный заголовок") {
  unsigned char buf[8]{};
  TransferPacket out{};
  REQUIRE_FALSE(packet::decode_file_transfer(buf, sizeof(buf), out));
}

TEST_CASE("packet decode: заявленная длина больше фактического тела") {
  const auto p0 = minimal_packet();
  std::vector<unsigned char> wire;
  REQUIRE(packet::encode_file_transfer(p0, wire));
  REQUIRE(wire.size() > protocol::kFileHeaderPrefixLen);
  wire.resize(protocol::kFileHeaderPrefixLen + 10);
  TransferPacket out{};
  REQUIRE_FALSE(packet::decode_file_transfer(wire.data(), wire.size(), out));
}

TEST_CASE("packet encode: неверная длина IV") {
  auto p = minimal_packet();
  p.iv.resize(11);
  std::vector<unsigned char> wire;
  REQUIRE_FALSE(packet::encode_file_transfer(p, wire));
}

TEST_CASE("packet encode_prefix согласован с cipher_len") {
  auto p0 = minimal_packet();
  std::vector<unsigned char> prefix;
  const std::uint64_t ct = 1024;
  REQUIRE(packet::encode_file_transfer_prefix(p0, ct, prefix));

  p0.ciphertext.assign(static_cast<std::size_t>(ct), static_cast<unsigned char>(0x55));
  std::vector<unsigned char> full;
  REQUIRE(packet::encode_file_transfer(p0, full));
  REQUIRE(full.size() == prefix.size() + static_cast<std::size_t>(ct));
  REQUIRE(std::memcmp(full.data(), prefix.data(), prefix.size()) == 0);
}
