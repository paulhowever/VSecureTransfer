#include "vsecure/replay.hpp"

#include <fstream>

namespace vsecure::replay {

std::string MessageIdStore::id_to_hex(const unsigned char id[16]) {
  static const char* hex = "0123456789abcdef";
  std::string s(32, ' ');
  for (int i = 0; i < 16; ++i) {
    s[static_cast<std::size_t>(i * 2)] = hex[(id[i] >> 4) & 0xF];
    s[static_cast<std::size_t>(i * 2 + 1)] = hex[id[i] & 0xF];
  }
  return s;
}

MessageIdStore::MessageIdStore(std::string persist_path) : path_(std::move(persist_path)) {
  std::ifstream in(path_, std::ios::binary);
  if (!in)
    return;
  std::string line;
  while (std::getline(in, line)) {
    if (line.size() >= 32)
      seen_.insert(line.substr(0, 32));
  }
}

bool MessageIdStore::is_replay(const unsigned char id[16]) const {
  return seen_.count(id_to_hex(id)) != 0;
}

void MessageIdStore::commit(const unsigned char id[16]) {
  const std::string h = id_to_hex(id);
  seen_.insert(h);
  std::ofstream out(path_, std::ios::app | std::ios::binary);
  if (out)
    out << h << '\n';
}

bool MessageIdStore::timestamp_ok(std::uint64_t now_ms, std::uint64_t msg_ms) {
  const std::uint64_t d = msg_ms > now_ms ? msg_ms - now_ms : now_ms - msg_ms;
  return d <= kTimestampWindowMs;
}

} // namespace vsecure::replay
