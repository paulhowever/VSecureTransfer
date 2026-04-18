#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vsecure::tcp {

bool write_all(int fd, const void* buf, std::size_t len);

bool read_all(int fd, void* buf, std::size_t len);

/** Отправка: 8 байт uint64_be длины тела, затем body. */
bool send_framed(int fd, const unsigned char* body, std::size_t body_len);

/** Приём одного фрейма в vector. */
bool recv_framed(int fd, std::vector<unsigned char>& out);

/** ACK 8 байт (см. protocol.hpp). */
bool send_ack(int fd, std::uint32_t status_be_host);

/** Читает ровно 8 байт ACK, возвращает status в host byte order. */
bool recv_ack(int fd, std::uint32_t& out_status_host);

int connect_tcp(const std::string& host, std::uint16_t port);

/** listen + accept один клиент; возвращает client fd, server fd для close. */
int accept_one(std::uint16_t port, int& out_listen_fd);

void close_fd(int fd);

} // namespace vsecure::tcp
