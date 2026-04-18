#include "vsecure/modules_tz.hpp"

#include "vsecure/packet.hpp"
#include "vsecure/tcp.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace vsecure::modules_tz {

bool FileReader::read_file_into_hasher(const std::string& path, crypto::Sha256Stream& hasher) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return false;
  char buf[65536];
  while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
    if (!hasher.update(buf, static_cast<std::size_t>(in.gcount())))
      return false;
  }
  return true;
}

bool Encryptor::encrypt_video_to_cipher_file(const unsigned char* aes_key32, const unsigned char* iv12,
                                             const std::string& plain_video_path,
                                             const std::string& cipher_out_path) {
  return crypto::aes256_gcm_encrypt_file_path_to_file(aes_key32, iv12, plain_video_path, cipher_out_path);
}

bool Signer::sign_rsa_pss_sha256(EVP_PKEY* sign_priv, const std::vector<unsigned char>& sign_input,
                                 std::vector<unsigned char>& out_signature) {
  return crypto::rsa_pss_sha256_sign(sign_priv, sign_input.data(), sign_input.size(), out_signature);
}

bool PacketBuilder::build_prefix(const TransferPacket& pkt, std::uint64_t ciphertext_byte_len,
                                 std::vector<unsigned char>& prefix_out) {
  return packet::encode_file_transfer_prefix(pkt, ciphertext_byte_len, prefix_out);
}

std::vector<unsigned char> PacketBuilder::signing_blob(const std::vector<unsigned char>& meta_wire,
                                                         const std::vector<unsigned char>& iv,
                                                         const std::vector<unsigned char>& wrapped_key) {
  return packet::signing_blob(meta_wire, iv, wrapped_key);
}

int ClientTransport::connect(const std::string& host, std::uint16_t port) { return tcp::connect_tcp(host, port); }

bool ClientTransport::send_framed_prefix_and_cipher_file(int fd, const std::vector<unsigned char>& prefix,
                                                         const std::string& cipher_file_path) {
  return tcp::send_framed_prefix_then_cipher_file(fd, prefix.data(), prefix.size(), cipher_file_path);
}

bool ClientTransport::recv_ack(int fd, std::uint32_t& out_status_host) { return tcp::recv_ack(fd, out_status_host); }

void ClientTransport::close(int fd) { tcp::close_fd(fd); }

int ServerTransport::accept_one_client(std::uint16_t port, int& out_listen_fd) {
  return tcp::accept_one(port, out_listen_fd);
}

bool ServerTransport::recv_framed_to_file(int client_fd, const std::string& body_path, std::uint64_t& out_len) {
  return tcp::recv_framed_to_file(client_fd, body_path, out_len);
}

bool ServerTransport::send_ack(int fd, std::uint32_t status_host) { return tcp::send_ack(fd, status_host); }

void ServerTransport::close(int fd) { tcp::close_fd(fd); }

bool PacketParser::parse_file_transfer(const unsigned char* data, std::size_t len, TransferPacket& out) {
  return packet::decode_file_transfer(data, len, out);
}

bool Verifier::rsa_pss_sha256_verify(EVP_PKEY* sign_pub, const unsigned char* msg, std::size_t msg_len,
                                      const unsigned char* sig, std::size_t sig_len) {
  return crypto::rsa_pss_sha256_verify(sign_pub, msg, msg_len, sig, sig_len);
}

bool Decryptor::aes256_gcm_to_file(const unsigned char* key32, const unsigned char* iv12,
                                   const unsigned char* cipher_with_tag, std::size_t len,
                                   const std::string& plain_out_path) {
  return crypto::aes256_gcm_decrypt_to_file(key32, iv12, cipher_with_tag, len, plain_out_path);
}

bool IntegrityChecker::sha256_file_matches(const std::string& path, const unsigned char expected[32]) {
  unsigned char got[32];
  if (!crypto::sha256_file(path, got))
    return false;
  return std::memcmp(got, expected, 32) == 0;
}

bool FileWriter::commit_temp_file(const std::string& temp_plain_path, const std::string& final_path) {
  std::error_code ec;
  std::filesystem::remove(final_path, ec);
  (void)ec;
  ec.clear();
  std::filesystem::rename(temp_plain_path, final_path, ec);
  return !ec;
}

} // namespace vsecure::modules_tz
