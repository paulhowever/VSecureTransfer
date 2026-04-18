#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "vsecure/protocol.hpp"

namespace vsecure {

struct FileMetadata {
  std::uint64_t original_size = 0;
  std::uint64_t unix_timestamp_ms = 0;
  unsigned char message_id[protocol::kMessageIdLen]{};
  unsigned char sha256_plaintext[protocol::kSha256Len]{};
  std::string filename_utf8;
};

struct TransferPacket {
  FileMetadata meta;
  std::vector<unsigned char> iv;           // 12 bytes
  std::vector<unsigned char> wrapped_key;  // RSA-OAEP output
  std::vector<unsigned char> signature;    // RSA-PSS
  std::vector<unsigned char> ciphertext;   // includes GCM tag at tail
};

} // namespace vsecure
