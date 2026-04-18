#include "vsecure/tcp.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "vsecure/endian.hpp"
#include "vsecure/protocol.hpp"

namespace vsecure::tcp {

using vsecure::endian::be64;

bool write_all(int fd, const void* buf, std::size_t len) {
  const auto* p = static_cast<const unsigned char*>(buf);
  std::size_t off = 0;
  while (off < len) {
    const ssize_t n = ::write(fd, p + off, len - off);
    if (n <= 0)
      return false;
    off += static_cast<std::size_t>(n);
  }
  return true;
}

bool read_all(int fd, void* buf, std::size_t len) {
  auto* p = static_cast<unsigned char*>(buf);
  std::size_t off = 0;
  while (off < len) {
    const ssize_t n = ::read(fd, p + off, len - off);
    if (n <= 0)
      return false;
    off += static_cast<std::size_t>(n);
  }
  return true;
}

bool send_framed(int fd, const unsigned char* body, std::size_t body_len) {
  std::uint64_t len_be = be64(static_cast<std::uint64_t>(body_len));
  if (!write_all(fd, &len_be, sizeof(len_be)))
    return false;
  if (body_len == 0)
    return true;
  return write_all(fd, body, body_len);
}

bool recv_framed(int fd, std::vector<unsigned char>& out) {
  std::uint64_t len_be = 0;
  if (!read_all(fd, &len_be, sizeof(len_be)))
    return false;
  const std::uint64_t len_host = be64(len_be);
  if (len_host > 1ull << 40)
    return false;
  out.resize(static_cast<std::size_t>(len_host));
  if (len_host == 0)
    return true;
  return read_all(fd, out.data(), static_cast<std::size_t>(len_host));
}

bool send_ack(int fd, std::uint32_t status_host) {
  unsigned char frame[protocol::kAckFrameLen];
  std::memcpy(frame, protocol::kAckMagic, 4);
  std::uint32_t st = vsecure::endian::be32(status_host);
  std::memcpy(frame + 4, &st, 4);
  return write_all(fd, frame, sizeof(frame));
}

bool recv_ack(int fd, std::uint32_t& out_status_host) {
  unsigned char frame[protocol::kAckFrameLen];
  if (!read_all(fd, frame, sizeof(frame)))
    return false;
  if (std::memcmp(frame, protocol::kAckMagic, 4) != 0)
    return false;
  std::uint32_t st = 0;
  std::memcpy(&st, frame + 4, 4);
  out_status_host = vsecure::endian::be32(st);
  return true;
}

int connect_tcp(const std::string& host, std::uint16_t port) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return -1;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

int accept_one(std::uint16_t port, int& out_listen_fd) {
  out_listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (out_listen_fd < 0)
    return -1;
  int yes = 1;
  (void)::setsockopt(out_listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  if (::bind(out_listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(out_listen_fd);
    out_listen_fd = -1;
    return -1;
  }
  if (::listen(out_listen_fd, 1) != 0) {
    ::close(out_listen_fd);
    out_listen_fd = -1;
    return -1;
  }
  const int client = ::accept(out_listen_fd, nullptr, nullptr);
  if (client < 0) {
    ::close(out_listen_fd);
    out_listen_fd = -1;
    return -1;
  }
  return client;
}

void close_fd(int fd) {
  if (fd >= 0)
    ::close(fd);
}

} // namespace vsecure::tcp
