#include "vsecure/event_journal.hpp"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>

namespace vsecure::event_journal {

namespace {

std::mutex g_mu;
std::unique_ptr<std::ofstream> g_stream;

std::string stamp_utc_ms() {
  using clock = std::chrono::system_clock;
  const auto now = clock::now();
  const auto sec = std::chrono::time_point_cast<std::chrono::seconds>(now);
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - sec).count();
  const std::time_t t = clock::to_time_t(sec);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  std::ostringstream o;
  o << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms << 'Z';
  return o.str();
}

} // namespace

bool open(const std::filesystem::path& out_dir) {
  std::lock_guard<std::mutex> lk(g_mu);
  g_stream.reset();
  const auto path = out_dir / "vsecure.log";
  auto f = std::make_unique<std::ofstream>(path, std::ios::app | std::ios::binary);
  if (!f->good())
    return false;
  g_stream = std::move(f);
  *g_stream << stamp_utc_ms() << " сессия приёма: журнал открыт\n";
  g_stream->flush();
  return true;
}

void line(const std::string& message) {
  std::lock_guard<std::mutex> lk(g_mu);
  if (!g_stream || !g_stream->good())
    return;
  *g_stream << stamp_utc_ms() << ' ' << message << '\n';
  g_stream->flush();
}

void close() {
  std::lock_guard<std::mutex> lk(g_mu);
  if (g_stream && g_stream->good())
    *g_stream << stamp_utc_ms() << " сессия приёма: журнал закрыт\n";
  g_stream.reset();
}

} // namespace vsecure::event_journal
