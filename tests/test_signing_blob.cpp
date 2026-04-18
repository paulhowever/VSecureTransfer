#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <vector>

#include "vsecure/packet.hpp"

using namespace vsecure;

TEST_CASE("signing_blob: конкатенация meta || iv || wrapped_key") {
  std::vector<unsigned char> meta = {0, 1, 2};
  std::vector<unsigned char> iv(12, 0xAA);
  std::vector<unsigned char> wrapped = {7, 8};

  const auto s = packet::signing_blob(meta, iv, wrapped);
  REQUIRE(s.size() == meta.size() + iv.size() + wrapped.size());

  std::size_t o = 0;
  REQUIRE(std::memcmp(s.data() + o, meta.data(), meta.size()) == 0);
  o += meta.size();
  REQUIRE(std::memcmp(s.data() + o, iv.data(), iv.size()) == 0);
  o += iv.size();
  REQUIRE(std::memcmp(s.data() + o, wrapped.data(), wrapped.size()) == 0);
}
