#pragma once

#include <cstdint>
#include <cstring>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

namespace vsecure::endian {

inline std::uint16_t be16(std::uint16_t v) {
  return static_cast<std::uint16_t>((v << 8) | (v >> 8));
}

inline std::uint32_t be32(std::uint32_t v) {
  return ((v & 0xFF000000u) >> 24) | ((v & 0x00FF0000u) >> 8) | ((v & 0x0000FF00u) << 8) |
         ((v & 0x000000FFu) << 24);
}

inline std::uint64_t be64(std::uint64_t v) {
  return ((v & 0xFF00000000000000ull) >> 56) | ((v & 0x00FF000000000000ull) >> 40) |
         ((v & 0x0000FF0000000000ull) >> 24) | ((v & 0x000000FF00000000ull) >> 8) |
         ((v & 0x00000000FF000000ull) << 8) | ((v & 0x0000000000FF0000ull) << 24) |
         ((v & 0x000000000000FF00ull) << 40) | ((v & 0x00000000000000FFull) << 56);
}

} // namespace vsecure::endian

#else
#error "Only little-endian hosts supported for now"
#endif
