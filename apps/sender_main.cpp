#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "vsecure/crypto.hpp"
#include "vsecure/metadata.hpp"
#include "vsecure/packet.hpp"
#include "vsecure/protocol.hpp"
#include "vsecure/tcp.hpp"
#include "vsecure/types.hpp"

namespace fs = std::filesystem;

static void usage() {
  std::cerr << "Использование: vsecure_sender --file ПУТЬ --host HOST --port ПОРТ \\\n"
                "            --sign-key ОТПРАВИТЕЛЬ_PRIV.pem --recv-pub ПОЛУЧАТЕЛЬ_WRAP_PUB.pem\n";
}

static std::uint64_t now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

static bool allowed_video_ext(const fs::path& p) {
  const std::string e = p.extension().string();
  return e == ".mp4" || e == ".avi" || e == ".mkv" || e == ".MP4" || e == ".AVI" || e == ".MKV";
}

static bool get_opt(int argc, char** argv, const char* key, std::string& out) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], key) == 0) {
      out = argv[i + 1];
      return true;
    }
  }
  return false;
}

int main(int argc, char** argv) {
  std::string file, host, port_str, sign_key, recv_pub;
  if (!get_opt(argc, argv, "--file", file) || !get_opt(argc, argv, "--host", host) ||
      !get_opt(argc, argv, "--port", port_str) || !get_opt(argc, argv, "--sign-key", sign_key) ||
      !get_opt(argc, argv, "--recv-pub", recv_pub)) {
    usage();
    return 2;
  }

  const int port = std::atoi(port_str.c_str());
  if (port <= 0 || port > 65535) {
    std::cerr << "Ошибка: некорректный порт.\n";
    return 2;
  }

  const fs::path fpath(file);
  if (!fs::exists(fpath) || !fs::is_regular_file(fpath)) {
    std::cerr << "Ошибка: файл не найден или недоступен.\n";
    return 1;
  }
  if (!allowed_video_ext(fpath)) {
    std::cerr << "Ошибка: допустимы расширения .mp4, .avi, .mkv.\n";
    return 1;
  }

  EVP_PKEY* sign_priv = nullptr;
  EVP_PKEY* wrap_pub = nullptr;
  if (!vsecure::crypto::load_private_pem(sign_key, &sign_priv) || !sign_priv) {
    std::cerr << "Ошибка: не удалось загрузить закрытый ключ подписи (--sign-key).\n";
    return 1;
  }
  if (!vsecure::crypto::load_public_pem(recv_pub, &wrap_pub) || !wrap_pub) {
    std::cerr << "Ошибка: не удалось загрузить открытый ключ получателя для обёртки (--recv-pub).\n";
    vsecure::crypto::free_pkey(sign_priv);
    return 1;
  }

  vsecure::crypto::Sha256Stream hasher;
  {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
      std::cerr << "Ошибка: не удалось открыть файл для чтения.\n";
      vsecure::crypto::free_pkey(sign_priv);
      vsecure::crypto::free_pkey(wrap_pub);
      return 1;
    }
    char buf[65536];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0)
      hasher.update(buf, static_cast<std::size_t>(in.gcount()));
  }

  vsecure::FileMetadata meta{};
  meta.original_size = fs::file_size(fpath);
  meta.unix_timestamp_ms = now_ms();
  vsecure::crypto::random_bytes(meta.message_id, sizeof(meta.message_id));
  if (!hasher.final(meta.sha256_plaintext)) {
    std::cerr << "Ошибка: не удалось завершить вычисление SHA-256.\n";
    vsecure::crypto::free_pkey(sign_priv);
    vsecure::crypto::free_pkey(wrap_pub);
    return 1;
  }
  meta.filename_utf8 = fpath.filename().string();
  if (meta.filename_utf8.size() > 1024 * 1024) {
    std::cerr << "Ошибка: слишком длинное имя файла.\n";
    vsecure::crypto::free_pkey(sign_priv);
    vsecure::crypto::free_pkey(wrap_pub);
    return 1;
  }

  unsigned char aes_key[32];
  unsigned char iv[vsecure::protocol::kGcmIvLen];
  vsecure::crypto::random_bytes(aes_key, sizeof(aes_key));
  vsecure::crypto::random_bytes(iv, sizeof(iv));

  std::vector<unsigned char> ciphertext;
  if (!vsecure::crypto::aes256_gcm_encrypt_file_path(aes_key, iv, file, ciphertext)) {
    std::cerr << "Ошибка: шифрование AES-256-GCM не удалось.\n";
    vsecure::crypto::free_pkey(sign_priv);
    vsecure::crypto::free_pkey(wrap_pub);
    return 1;
  }

  std::vector<unsigned char> wrapped;
  if (!vsecure::crypto::rsa_oaep_sha256_wrap(wrap_pub, aes_key, sizeof(aes_key), wrapped)) {
    std::cerr << "Ошибка: RSA-OAEP обёртка ключа не удалась.\n";
    std::memset(aes_key, 0, sizeof(aes_key));
    vsecure::crypto::free_pkey(sign_priv);
    vsecure::crypto::free_pkey(wrap_pub);
    return 1;
  }

  const std::vector<unsigned char> meta_wire = vsecure::metadata::serialize(meta);
  std::vector<unsigned char> iv_vec(iv, iv + sizeof(iv));
  const auto sign_input = vsecure::packet::signing_blob(meta_wire, iv_vec, wrapped);

  std::vector<unsigned char> signature;
  if (!vsecure::crypto::rsa_pss_sha256_sign(sign_priv, sign_input.data(), sign_input.size(), signature)) {
    std::cerr << "Ошибка: формирование RSA-PSS подписи не удалось.\n";
    std::memset(aes_key, 0, sizeof(aes_key));
    vsecure::crypto::free_pkey(sign_priv);
    vsecure::crypto::free_pkey(wrap_pub);
    return 1;
  }

  vsecure::TransferPacket pkt{};
  pkt.meta = meta;
  pkt.iv = iv_vec;
  pkt.wrapped_key = std::move(wrapped);
  pkt.signature = std::move(signature);
  pkt.ciphertext = std::move(ciphertext);

  std::vector<unsigned char> wire;
  if (!vsecure::packet::encode_file_transfer(pkt, wire)) {
    std::cerr << "Ошибка: сборка пакета не удалась.\n";
    std::memset(aes_key, 0, sizeof(aes_key));
    vsecure::crypto::free_pkey(sign_priv);
    vsecure::crypto::free_pkey(wrap_pub);
    return 1;
  }
  std::memset(aes_key, 0, sizeof(aes_key));

  if (const char* dump = std::getenv("VSECURE_DUMP_PACKET")) {
    if (*dump) {
      std::ofstream df(dump, std::ios::binary | std::ios::trunc);
      if (!df.write(reinterpret_cast<const char*>(wire.data()), static_cast<std::streamsize>(wire.size())))
        std::cerr << "Предупреждение: не удалось записать дамп пакета (VSECURE_DUMP_PACKET).\n";
    }
  }

  const auto t0 = std::chrono::steady_clock::now();
  const int fd = vsecure::tcp::connect_tcp(host, static_cast<std::uint16_t>(port));
  if (fd < 0) {
    std::cerr << "Ошибка: сервер недоступен или неверный адрес (TCP connect).\n";
    vsecure::crypto::free_pkey(sign_priv);
    vsecure::crypto::free_pkey(wrap_pub);
    return 1;
  }

  if (!vsecure::tcp::send_framed(fd, wire.data(), wire.size())) {
    std::cerr << "Ошибка: разрыв соединения при отправке пакета.\n";
    vsecure::tcp::close_fd(fd);
    vsecure::crypto::free_pkey(sign_priv);
    vsecure::crypto::free_pkey(wrap_pub);
    return 1;
  }

  std::uint32_t ack = 0;
  if (!vsecure::tcp::recv_ack(fd, ack)) {
    std::cerr << "Ошибка: не получен ACK от получателя (разрыв соединения).\n";
    vsecure::tcp::close_fd(fd);
    vsecure::crypto::free_pkey(sign_priv);
    vsecure::crypto::free_pkey(wrap_pub);
    return 1;
  }
  vsecure::tcp::close_fd(fd);
  vsecure::crypto::free_pkey(sign_priv);
  vsecure::crypto::free_pkey(wrap_pub);

  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
                      .count();

  if (ack == vsecure::protocol::kAckOk) {
    std::cout << "Передача выполнена успешно за " << ms << " мс.\n";
    return 0;
  }
  if (ack == vsecure::protocol::kAckBadSignature)
    std::cerr << "Ошибка на стороне получателя: подпись неверна.\n";
  else if (ack == vsecure::protocol::kAckReplay)
    std::cerr << "Ошибка на стороне получателя: повторное сообщение (message_id).\n";
  else if (ack == vsecure::protocol::kAckTimeSkew)
    std::cerr << "Ошибка на стороне получателя: временная метка вне допустимого окна.\n";
  else if (ack == vsecure::protocol::kAckHashMismatch)
    std::cerr << "Ошибка на стороне получателя: несовпадение хэша после расшифрования.\n";
  else if (ack == vsecure::protocol::kAckDecryptFailed)
    std::cerr << "Ошибка на стороне получателя: ошибка расшифрования.\n";
  else if (ack == vsecure::protocol::kAckIoError)
    std::cerr << "Ошибка на стороне получателя: ошибка записи файла на диск.\n";
  else if (ack == vsecure::protocol::kAckBadFormat)
    std::cerr << "Ошибка на стороне получателя: повреждённый или некорректный пакет.\n";
  else
    std::cerr << "Ошибка на стороне получателя: код " << ack << ".\n";
  return 1;
}
