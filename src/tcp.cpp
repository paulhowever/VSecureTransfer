#include "vsecure/tcp.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>

#include "vsecure/protocol.hpp"
#include "vsecure/wire_format.hpp"

namespace vsecure::tcp {

namespace {

constexpr int kConnectPollMs = 30000;
constexpr int kAcceptPollMs = 120000;
constexpr int kIoTimeoutSec = 600;

/** Подключение с уже известным sockaddr (IPv4/IPv6). */
bool connect_nonblocking_sockaddr(int fd, const sockaddr* sa, socklen_t salen) {
  const int fl = ::fcntl(fd, F_GETFL, 0);
  if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0)
    return false;
  const int cr = ::connect(fd, sa, salen);
  if (cr != 0 && errno != EINPROGRESS)
    return false;
  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLOUT;
  const int pr = ::poll(&pfd, 1, kConnectPollMs);
  if (pr <= 0)
    return false;
  int soerr = 0;
  socklen_t slen = sizeof(soerr);
  if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 || soerr != 0)
    return false;
  if (::fcntl(fd, F_SETFL, fl) != 0)
    return false;
  return set_socket_timeouts(fd, kIoTimeoutSec);
}

} // namespace

bool set_socket_timeouts(int fd, int seconds) {
  if (fd < 0 || seconds <= 0)
    return false;
  timeval tv{};
  tv.tv_sec = seconds;
  if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
    return false;
  if (::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
    return false;
  return true;
}

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
  unsigned char lenb[8];
  wire::store_u64_be(lenb, static_cast<std::uint64_t>(body_len));
  if (!write_all(fd, lenb, sizeof(lenb)))
    return false;
  if (body_len == 0)
    return true;
  return write_all(fd, body, body_len);
}

bool send_framed_prefix_then_cipher_file(int fd, const unsigned char* prefix, std::size_t prefix_len,
                                         const std::string& cipher_file_path) {
  FILE* cf = std::fopen(cipher_file_path.c_str(), "rb");
  if (!cf)
    return false;
  if (std::fseek(cf, 0, SEEK_END) != 0) {
    std::fclose(cf);
    return false;
  }
  const long csz = std::ftell(cf);
  if (csz < 0) {
    std::fclose(cf);
    return false;
  }
  if (std::fseek(cf, 0, SEEK_SET) != 0) {
    std::fclose(cf);
    return false;
  }
  const std::uint64_t total = static_cast<std::uint64_t>(prefix_len) + static_cast<std::uint64_t>(csz);
  if (total > (1ull << 40)) {
    std::fclose(cf);
    return false;
  }
  unsigned char lenb[8];
  wire::store_u64_be(lenb, total);
  if (!write_all(fd, lenb, sizeof(lenb))) {
    std::fclose(cf);
    return false;
  }
  if (!write_all(fd, prefix, prefix_len)) {
    std::fclose(cf);
    return false;
  }
  unsigned char buf[65536];
  long left = csz;
  while (left > 0) {
    const std::size_t nwant = static_cast<std::size_t>(std::min<long>(sizeof(buf), left));
    const std::size_t nrd = std::fread(buf, 1, nwant, cf);
    if (nrd != nwant) {
      std::fclose(cf);
      return false;
    }
    if (!write_all(fd, buf, nrd)) {
      std::fclose(cf);
      return false;
    }
    left -= static_cast<long>(nrd);
  }
  std::fclose(cf);
  return true;
}

bool recv_framed(int fd, std::vector<unsigned char>& out) {
  unsigned char lenb[8];
  if (!read_all(fd, lenb, sizeof(lenb)))
    return false;
  const std::uint64_t len_host = wire::load_u64_be(lenb);
  if (len_host > 1ull << 40)
    return false;
  out.resize(static_cast<std::size_t>(len_host));
  if (len_host == 0)
    return true;
  return read_all(fd, out.data(), static_cast<std::size_t>(len_host));
}

bool recv_framed_to_file(int fd, const std::string& path, std::uint64_t& out_body_len) {
  unsigned char lenb[8];
  if (!read_all(fd, lenb, sizeof(lenb)))
    return false;
  const std::uint64_t len_host = wire::load_u64_be(lenb);
  if (len_host > 1ull << 40)
    return false;
  out_body_len = len_host;
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f)
    return false;
  unsigned char buf[65536];
  std::uint64_t left = len_host;
  while (left > 0) {
    const std::size_t chunk = static_cast<std::size_t>(std::min<std::uint64_t>(sizeof(buf), left));
    if (!read_all(fd, buf, chunk)) {
      std::fclose(f);
      std::remove(path.c_str());
      return false;
    }
    if (std::fwrite(buf, 1, chunk, f) != chunk) {
      std::fclose(f);
      std::remove(path.c_str());
      return false;
    }
    left -= chunk;
  }
  std::fclose(f);
  return true;
}

bool send_ack(int fd, std::uint32_t status_host) {
  unsigned char frame[protocol::kAckFrameLen];
  std::memcpy(frame, protocol::kAckMagic, 4);
  unsigned char stb[4];
  wire::store_u32_be(stb, status_host);
  std::memcpy(frame + 4, stb, 4);
  return write_all(fd, frame, sizeof(frame));
}

bool recv_ack(int fd, std::uint32_t& out_status_host) {
  unsigned char frame[protocol::kAckFrameLen];
  if (!read_all(fd, frame, sizeof(frame)))
    return false;
  if (std::memcmp(frame, protocol::kAckMagic, 4) != 0)
    return false;
  out_status_host = wire::load_u32_be(frame + 4);
  return true;
}

int connect_tcp(const std::string& host, std::uint16_t port) {
  char serv[16];
  if (std::snprintf(serv, sizeof(serv), "%u", static_cast<unsigned>(port)) <= 0)
    return -1;

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo* res = nullptr;
  const int gai = ::getaddrinfo(host.c_str(), serv, &hints, &res);
  if (gai != 0 || res == nullptr)
    return -1;

  std::vector<addrinfo*> ordered;
  ordered.reserve(8);
  for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
    if (p->ai_family == AF_INET6)
      ordered.push_back(p);
  }
  for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
    if (p->ai_family == AF_INET)
      ordered.push_back(p);
  }
  if (ordered.empty()) {
    for (addrinfo* p = res; p != nullptr; p = p->ai_next)
      ordered.push_back(p);
  }

  for (addrinfo* p : ordered) {
    const int fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0)
      continue;
    if (!connect_nonblocking_sockaddr(fd, p->ai_addr, static_cast<socklen_t>(p->ai_addrlen))) {
      ::close(fd);
      continue;
    }
    ::freeaddrinfo(res);
    return fd;
  }
  ::freeaddrinfo(res);
  return -1;
}

int accept_one(std::uint16_t port, int& out_listen_fd) {
  char serv[16];
  if (std::snprintf(serv, sizeof(serv), "%u", static_cast<unsigned>(port)) <= 0) {
    out_listen_fd = -1;
    return -1;
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  addrinfo* res = nullptr;
  if (::getaddrinfo(nullptr, serv, &hints, &res) != 0) {
    out_listen_fd = -1;
    return -1;
  }

  int listen_fd = -1;
  for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
    if (p->ai_family != AF_INET6)
      continue;
    listen_fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (listen_fd < 0)
      continue;
    int yes = 1;
    (void)::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
    int v6only = 0;
    (void)::setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
#endif
    if (::bind(listen_fd, p->ai_addr, static_cast<socklen_t>(p->ai_addrlen)) == 0)
      break;
    ::close(listen_fd);
    listen_fd = -1;
  }

  if (listen_fd < 0) {
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
      if (p->ai_family != AF_INET)
        continue;
      listen_fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (listen_fd < 0)
        continue;
      int yes = 1;
      (void)::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
      if (::bind(listen_fd, p->ai_addr, static_cast<socklen_t>(p->ai_addrlen)) == 0)
        break;
      ::close(listen_fd);
      listen_fd = -1;
    }
  }

  ::freeaddrinfo(res);

  if (listen_fd < 0) {
    out_listen_fd = -1;
    return -1;
  }

  out_listen_fd = listen_fd;
  if (::listen(listen_fd, 1) != 0) {
    ::close(listen_fd);
    out_listen_fd = -1;
    return -1;
  }

  pollfd pfd{};
  pfd.fd = listen_fd;
  pfd.events = POLLIN;
  if (::poll(&pfd, 1, kAcceptPollMs) <= 0) {
    ::close(listen_fd);
    out_listen_fd = -1;
    return -1;
  }
  const int client = ::accept(listen_fd, nullptr, nullptr);
  if (client < 0) {
    ::close(listen_fd);
    out_listen_fd = -1;
    return -1;
  }
  if (!set_socket_timeouts(client, kIoTimeoutSec)) {
    ::close(client);
    ::close(listen_fd);
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
