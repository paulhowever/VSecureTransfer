#pragma once

#include <cstdint>
#include <set>
#include <string>

namespace vsecure::replay {

/** Окно времени в миллисекундах (± от текущего времени получателя). */
inline constexpr std::uint64_t kTimestampWindowMs = 300'000;

class MessageIdStore {
public:
  explicit MessageIdStore(std::string persist_path);

  /** true если id уже встречался (повтор). */
  bool is_replay(const unsigned char id[16]) const;

  /** Зафиксировать успешно принятый id (память + append в файл). */
  void commit(const unsigned char id[16]);

  static bool timestamp_ok(std::uint64_t now_ms, std::uint64_t msg_ms);

private:
  static std::string id_to_hex(const unsigned char id[16]);

  std::string path_;
  std::set<std::string> seen_;
};

} // namespace vsecure::replay
