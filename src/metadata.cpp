#include "vsecure/metadata.hpp"

#include <cstring>

#include "vsecure/endian.hpp"
#include "vsecure/protocol.hpp"

namespace vsecure::metadata {

using vsecure::endian::be32;
using vsecure::endian::be64;

std::vector<unsigned char> serialize(const FileMetadata& m) {
  std::vector<unsigned char> out;
  if (m.filename_utf8.size() > 0xFFFFFFu)
    return out;

  const std::uint32_t name_len = static_cast<std::uint32_t>(m.filename_utf8.size());
  out.reserve(8 + 8 + 16 + 32 + 4 + name_len);

  auto push_u64 = [&out](std::uint64_t v) {
    v = be64(v);
    const auto* p = reinterpret_cast<const unsigned char*>(&v);
    out.insert(out.end(), p, p + 8);
  };
  auto push_u32 = [&out](std::uint32_t v) {
    v = be32(v);
    const auto* p = reinterpret_cast<const unsigned char*>(&v);
    out.insert(out.end(), p, p + 4);
  };

  push_u64(m.original_size);
  push_u64(m.unix_timestamp_ms);
  out.insert(out.end(), m.message_id, m.message_id + protocol::kMessageIdLen);
  out.insert(out.end(), m.sha256_plaintext, m.sha256_plaintext + protocol::kSha256Len);
  push_u32(name_len);
  out.insert(out.end(), m.filename_utf8.begin(), m.filename_utf8.end());
  return out;
}

bool parse(const unsigned char* data, std::size_t len, FileMetadata& out) {
  if (len < 8 + 8 + 16 + 32 + 4)
    return false;
  std::size_t o = 0;
  auto read_u64 = [&]() -> std::uint64_t {
    std::uint64_t v = 0;
    std::memcpy(&v, data + o, 8);
    o += 8;
    return be64(v);
  };
  auto read_u32 = [&]() -> std::uint32_t {
    std::uint32_t v = 0;
    std::memcpy(&v, data + o, 4);
    o += 4;
    return be32(v);
  };

  out = FileMetadata{};
  out.original_size = read_u64();
  out.unix_timestamp_ms = read_u64();
  std::memcpy(out.message_id, data + o, protocol::kMessageIdLen);
  o += protocol::kMessageIdLen;
  std::memcpy(out.sha256_plaintext, data + o, protocol::kSha256Len);
  o += protocol::kSha256Len;
  const std::uint32_t name_len = read_u32();
  if (o + name_len > len)
    return false;
  out.filename_utf8.assign(reinterpret_cast<const char*>(data + o), reinterpret_cast<const char*>(data + o + name_len));
  return true;
}

} // namespace vsecure::metadata
