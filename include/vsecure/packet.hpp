#pragma once

#include <cstdint>
#include <vector>

#include "vsecure/types.hpp"

namespace vsecure::packet {

/** Полный payload пакета FileTransfer (без uint64 длины фрейма TCP). */
bool encode_file_transfer(const TransferPacket& p, std::vector<unsigned char>& out);

bool decode_file_transfer(const unsigned char* data, std::size_t len, TransferPacket& out);

/** Байты, которые подписываются: meta || iv || wrapped_key (см. protocol.hpp). */
std::vector<unsigned char> signing_blob(const std::vector<unsigned char>& meta_wire,
                                         const std::vector<unsigned char>& iv,
                                         const std::vector<unsigned char>& wrapped_key);

} // namespace vsecure::packet
