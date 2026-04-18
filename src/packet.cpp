#include "vsecure/packet.hpp"

#include <cstring>

#include "vsecure/metadata.hpp"
#include "vsecure/protocol.hpp"
#include "vsecure/wire_format.hpp"

namespace vsecure::packet {

static void push_u32(std::vector<unsigned char>& v, std::uint32_t x) {
  unsigned char b[4];
  wire::store_u32_be(b, x);
  v.insert(v.end(), b, b + 4);
}

static void push_u64(std::vector<unsigned char>& v, std::uint64_t x) {
  unsigned char b[8];
  wire::store_u64_be(b, x);
  v.insert(v.end(), b, b + 8);
}

static std::uint32_t read_u32(const unsigned char*& cur, std::size_t& rem) {
  if (rem < 4)
    return 0;
  const std::uint32_t v = wire::load_u32_be(cur);
  cur += 4;
  rem -= 4;
  return v;
}

static std::uint64_t read_u64(const unsigned char*& cur, std::size_t& rem) {
  if (rem < 8)
    return 0;
  const std::uint64_t v = wire::load_u64_be(cur);
  cur += 8;
  rem -= 8;
  return v;
}

std::vector<unsigned char> signing_blob(const std::vector<unsigned char>& meta_wire,
                                         const std::vector<unsigned char>& iv,
                                         const std::vector<unsigned char>& wrapped_key) {
  std::vector<unsigned char> s;
  s.reserve(meta_wire.size() + iv.size() + wrapped_key.size());
  s.insert(s.end(), meta_wire.begin(), meta_wire.end());
  s.insert(s.end(), iv.begin(), iv.end());
  s.insert(s.end(), wrapped_key.begin(), wrapped_key.end());
  return s;
}

bool encode_file_transfer(const TransferPacket& p, std::vector<unsigned char>& out) {
  if (p.iv.size() != protocol::kGcmIvLen)
    return false;
  if (p.ciphertext.size() < protocol::kGcmTagLen)
    return false;

  const std::vector<unsigned char> meta_wire = vsecure::metadata::serialize(p.meta);
  if (meta_wire.size() < 8 + 8 + 16 + 32 + 4)
    return false;

  out.clear();
  out.reserve(protocol::kFileHeaderPrefixLen + meta_wire.size() + p.iv.size() + p.wrapped_key.size() +
               p.signature.size() + p.ciphertext.size());

  out.insert(out.end(), protocol::kMagic, protocol::kMagic + 4);
  unsigned char verb[2];
  wire::store_u16_be(verb, protocol::kProtocolVersion);
  out.insert(out.end(), verb, verb + 2);
  out.push_back(protocol::kMsgFileTransfer);
  out.push_back(0);

  push_u32(out, static_cast<std::uint32_t>(meta_wire.size()));
  push_u32(out, static_cast<std::uint32_t>(p.wrapped_key.size()));
  push_u32(out, static_cast<std::uint32_t>(p.signature.size()));
  push_u64(out, static_cast<std::uint64_t>(p.ciphertext.size()));

  out.insert(out.end(), meta_wire.begin(), meta_wire.end());
  out.insert(out.end(), p.iv.begin(), p.iv.end());
  out.insert(out.end(), p.wrapped_key.begin(), p.wrapped_key.end());
  out.insert(out.end(), p.signature.begin(), p.signature.end());
  out.insert(out.end(), p.ciphertext.begin(), p.ciphertext.end());
  return true;
}

/** Собирает все байты пакета до ciphertext (для потоковой отправки шифротекста с диска). */
bool encode_file_transfer_prefix(const TransferPacket& p, std::uint64_t ciphertext_len,
                                   std::vector<unsigned char>& prefix_out) {
  if (p.iv.size() != protocol::kGcmIvLen)
    return false;
  if (ciphertext_len < protocol::kGcmTagLen)
    return false;

  const std::vector<unsigned char> meta_wire = vsecure::metadata::serialize(p.meta);
  if (meta_wire.size() < 8 + 8 + 16 + 32 + 4)
    return false;

  prefix_out.clear();
  prefix_out.reserve(protocol::kFileHeaderPrefixLen + meta_wire.size() + p.iv.size() + p.wrapped_key.size() +
                      p.signature.size());

  prefix_out.insert(prefix_out.end(), protocol::kMagic, protocol::kMagic + 4);
  unsigned char verb[2];
  wire::store_u16_be(verb, protocol::kProtocolVersion);
  prefix_out.insert(prefix_out.end(), verb, verb + 2);
  prefix_out.push_back(protocol::kMsgFileTransfer);
  prefix_out.push_back(0);

  push_u32(prefix_out, static_cast<std::uint32_t>(meta_wire.size()));
  push_u32(prefix_out, static_cast<std::uint32_t>(p.wrapped_key.size()));
  push_u32(prefix_out, static_cast<std::uint32_t>(p.signature.size()));
  push_u64(prefix_out, ciphertext_len);

  prefix_out.insert(prefix_out.end(), meta_wire.begin(), meta_wire.end());
  prefix_out.insert(prefix_out.end(), p.iv.begin(), p.iv.end());
  prefix_out.insert(prefix_out.end(), p.wrapped_key.begin(), p.wrapped_key.end());
  prefix_out.insert(prefix_out.end(), p.signature.begin(), p.signature.end());
  return true;
}

bool decode_file_transfer(const unsigned char* data, std::size_t len, TransferPacket& out) {
  out = TransferPacket{};
  if (len < protocol::kFileHeaderPrefixLen)
    return false;
  if (std::memcmp(data, protocol::kMagic, 4) != 0)
    return false;
  if (wire::load_u16_be(data + 4) != protocol::kProtocolVersion)
    return false;
  if (data[6] != protocol::kMsgFileTransfer)
    return false;

  const unsigned char* cur = data + 8;
  std::size_t rem = len - 8;
  const std::uint32_t meta_len = read_u32(cur, rem);
  const std::uint32_t wrapped_len = read_u32(cur, rem);
  const std::uint32_t sig_len = read_u32(cur, rem);
  const std::uint64_t cipher_len = read_u64(cur, rem);
  if (meta_len == 0 && wrapped_len == 0)
    return false;
  const std::size_t need = static_cast<std::size_t>(meta_len) + protocol::kGcmIvLen +
                           static_cast<std::size_t>(wrapped_len) + static_cast<std::size_t>(sig_len) +
                           static_cast<std::size_t>(cipher_len);
  if (need > rem)
    return false;

  if (!vsecure::metadata::parse(cur, meta_len, out.meta))
    return false;
  cur += meta_len;
  rem -= meta_len;

  out.iv.assign(cur, cur + protocol::kGcmIvLen);
  cur += protocol::kGcmIvLen;
  rem -= protocol::kGcmIvLen;

  out.wrapped_key.assign(cur, cur + wrapped_len);
  cur += wrapped_len;
  rem -= wrapped_len;

  out.signature.assign(cur, cur + sig_len);
  cur += sig_len;
  rem -= sig_len;

  out.ciphertext.assign(cur, cur + static_cast<std::size_t>(cipher_len));
  return out.iv.size() == protocol::kGcmIvLen && out.ciphertext.size() == cipher_len;
}

} // namespace vsecure::packet
