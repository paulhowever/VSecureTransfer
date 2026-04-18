#pragma once

#include <cstdint>
#include <cstring>

/** Явная сериализация big-endian без зависимости от порядка байт хоста (ТЗ: network byte order). */
namespace vsecure::wire {

inline void store_u16_be(unsigned char* p, std::uint16_t v) {
  p[0] = static_cast<unsigned char>((v >> 8) & 0xFF);
  p[1] = static_cast<unsigned char>(v & 0xFF);
}

inline std::uint16_t load_u16_be(const unsigned char* p) {
  return static_cast<std::uint16_t>(p[0]) << 8 | static_cast<std::uint16_t>(p[1]);
}

inline void store_u32_be(unsigned char* p, std::uint32_t v) {
  p[0] = static_cast<unsigned char>((v >> 24) & 0xFF);
  p[1] = static_cast<unsigned char>((v >> 16) & 0xFF);
  p[2] = static_cast<unsigned char>((v >> 8) & 0xFF);
  p[3] = static_cast<unsigned char>(v & 0xFF);
}

inline std::uint32_t load_u32_be(const unsigned char* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

inline void store_u64_be(unsigned char* p, std::uint64_t v) {
  for (int i = 0; i < 8; ++i)
    p[i] = static_cast<unsigned char>((v >> (56 - 8 * i)) & 0xFF);
}

inline std::uint64_t load_u64_be(const unsigned char* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i)
    v = (v << 8) | p[i];
  return v;
}

} // namespace vsecure::wire
