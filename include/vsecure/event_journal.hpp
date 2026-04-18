#pragma once

#include <filesystem>
#include <string>

namespace vsecure::event_journal {

/** Журнал событий получателя: append в `out_dir/vsecure.log` (ТЗ п.12). */
bool open(const std::filesystem::path& out_dir);
void line(const std::string& message);
void close();

} // namespace vsecure::event_journal
