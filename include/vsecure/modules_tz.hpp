#pragma once

/**
 * Именованные модули по п.15 ТЗ (отправитель / получатель).
 * Реализации в modules_tz.cpp; вызываются из sender_run / receiver_run.
 */
#include <cstdint>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "vsecure/crypto.hpp"
#include "vsecure/types.hpp"

namespace vsecure::modules_tz {

// --- Отправитель (ТЗ п.15) ---
struct FileReader {
  static bool read_file_into_hasher(const std::string& path, crypto::Sha256Stream& hasher);
};

struct Encryptor {
  static bool encrypt_video_to_cipher_file(const unsigned char* aes_key32, const unsigned char* iv12,
                                           const std::string& plain_video_path,
                                           const std::string& cipher_out_path);
};

struct Signer {
  static bool sign_rsa_pss_sha256(EVP_PKEY* sign_priv, const std::vector<unsigned char>& sign_input,
                                   std::vector<unsigned char>& out_signature);
};

struct PacketBuilder {
  static bool build_prefix(const TransferPacket& pkt, std::uint64_t ciphertext_byte_len,
                           std::vector<unsigned char>& prefix_out);
  static std::vector<unsigned char> signing_blob(const std::vector<unsigned char>& meta_wire,
                                                   const std::vector<unsigned char>& iv,
                                                   const std::vector<unsigned char>& wrapped_key);
};

struct ClientTransport {
  static int connect(const std::string& host, std::uint16_t port);
  static bool send_framed_prefix_and_cipher_file(int fd, const std::vector<unsigned char>& prefix,
                                                  const std::string& cipher_file_path);
  static bool recv_ack(int fd, std::uint32_t& out_status_host);
  static void close(int fd);
};

// --- Получатель (ТЗ п.15) ---
struct ServerTransport {
  static int accept_one_client(std::uint16_t port, int& out_listen_fd);
  static bool recv_framed_to_file(int client_fd, const std::string& body_path, std::uint64_t& out_len);
  static bool send_ack(int fd, std::uint32_t status_host);
  static void close(int fd);
};

struct PacketParser {
  static bool parse_file_transfer(const unsigned char* data, std::size_t len, TransferPacket& out);
};

struct Verifier {
  static bool rsa_pss_sha256_verify(EVP_PKEY* sign_pub, const unsigned char* msg, std::size_t msg_len,
                                    const unsigned char* sig, std::size_t sig_len);
};

struct Decryptor {
  static bool aes256_gcm_to_file(const unsigned char* key32, const unsigned char* iv12,
                                 const unsigned char* cipher_with_tag, std::size_t len,
                                 const std::string& plain_out_path);
};

struct IntegrityChecker {
  static bool sha256_file_matches(const std::string& path, const unsigned char expected[32]);
};

struct FileWriter {
  /** Атомарная замена: запись во временный файл и std::filesystem::rename. */
  static bool commit_temp_file(const std::string& temp_plain_path, const std::string& final_path);
};

} // namespace vsecure::modules_tz
