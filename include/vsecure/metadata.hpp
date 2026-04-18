#pragma once

#include <vector>

#include "vsecure/types.hpp"

namespace vsecure::metadata {

/** Сериализация метаданных в wire-формат (см. protocol.hpp). */
std::vector<unsigned char> serialize(const FileMetadata& m);

/** Парсинг; при ошибке возвращает false. */
bool parse(const unsigned char* data, std::size_t len, FileMetadata& out);

} // namespace vsecure::metadata
