#include "vsecure/metadata.hpp"

#include <cstring>

#include "vsecure/protocol.hpp"
#include "vsecure/wire_format.hpp"

namespace vsecure::metadata {

std::vector<unsigned char> serialize(const FileMetadata& m) {
  std::vector<unsigned char> out;
  if (m.filename_utf8.size() > 0xFFFFFFu)
    return out;

  const std::uint32_t name_len = static_cast<std::uint32_t>(m.filename_utf8.size());
  out.reserve(8 + 8 + 16 + 32 + 4 + name_len);

  unsigned char u8[8];
  wire::store_u64_be(u8, m.original_size);
  out.insert(out.end(), u8, u8 + 8);
  wire::store_u64_be(u8, m.unix_timestamp_ms);
  out.insert(out.end(), u8, u8 + 8);
  out.insert(out.end(), m.message_id, m.message_id + protocol::kMessageIdLen);
  out.insert(out.end(), m.sha256_plaintext, m.sha256_plaintext + protocol::kSha256Len);
  unsigned char u4[4];
  wire::store_u32_be(u4, name_len);
  out.insert(out.end(), u4, u4 + 4);
  out.insert(out.end(), m.filename_utf8.begin(), m.filename_utf8.end());
  return out;
}

bool parse(const unsigned char* data, std::size_t len, FileMetadata& out) {
  if (len < 8 + 8 + 16 + 32 + 4)
    return false;
  std::size_t o = 0;
  out = FileMetadata{};
  out.original_size = wire::load_u64_be(data + o);
  o += 8;
  out.unix_timestamp_ms = wire::load_u64_be(data + o);
  o += 8;
  std::memcpy(out.message_id, data + o, protocol::kMessageIdLen);
  o += protocol::kMessageIdLen;
  std::memcpy(out.sha256_plaintext, data + o, protocol::kSha256Len);
  o += protocol::kSha256Len;
  const std::uint32_t name_len = wire::load_u32_be(data + o);
  o += 4;
  if (o + name_len > len)
    return false;
  out.filename_utf8.assign(reinterpret_cast<const char*>(data + o), reinterpret_cast<const char*>(data + o + name_len));
  return true;
}

} // namespace vsecure::metadata
