#include "vsecure/sender_run.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <unistd.h>

#include "vsecure/crypto.hpp"
#include "vsecure/metadata.hpp"
#include "vsecure/modules_tz.hpp"
#include "vsecure/protocol.hpp"
#include "vsecure/types.hpp"

namespace fs = std::filesystem;

namespace vsecure {

namespace {

void usage() {
  std::cerr << "Использование: vsecure_sender --file ПУТЬ --host HOST --port ПОРТ \\\n"
                "            --sign-key ОТПРАВИТЕЛЬ_PRIV.pem --recv-pub ПОЛУЧАТЕЛЬ_WRAP_PUB.pem\n"
                "Открытый ключ получателя: PEM SPKI или X.509 сертификат.\n";
}

std::uint64_t now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

bool allowed_video_ext(const fs::path& p) {
  const std::string e = p.extension().string();
  return e == ".mp4" || e == ".avi" || e == ".mkv" || e == ".MP4" || e == ".AVI" || e == ".MKV";
}

bool get_opt(int argc, char** argv, const char* key, std::string& out) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], key) == 0) {
      out = argv[i + 1];
      return true;
    }
  }
  return false;
}

} // namespace

int run_secure_sender(int argc, char** argv) {
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
  if (!crypto::load_private_pem(sign_key, &sign_priv) || !sign_priv) {
    std::cerr << "Ошибка: не удалось загрузить закрытый ключ подписи (--sign-key).\n";
    return 1;
  }
  if (!crypto::load_public_pem(recv_pub, &wrap_pub) || !wrap_pub) {
    std::cerr << "Ошибка: не удалось загрузить открытый ключ/сертификат получателя (--recv-pub).\n";
    crypto::free_pkey(sign_priv);
    return 1;
  }

  crypto::Sha256Stream hasher;
  if (!modules_tz::FileReader::read_file_into_hasher(file, hasher)) {
    std::cerr << "Ошибка: не удалось прочитать файл для SHA-256.\n";
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }

  vsecure::FileMetadata meta{};
  meta.original_size = fs::file_size(fpath);
  meta.unix_timestamp_ms = now_ms();
  if (!crypto::random_bytes(meta.message_id, sizeof(meta.message_id))) {
    std::cerr << "Ошибка: генерация message_id (RAND_bytes) не удалась.\n";
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }
  if (!hasher.final(meta.sha256_plaintext)) {
    std::cerr << "Ошибка: не удалось завершить вычисление SHA-256.\n";
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }
  meta.filename_utf8 = fpath.filename().string();
  if (meta.filename_utf8.size() > 1024 * 1024) {
    std::cerr << "Ошибка: слишком длинное имя файла.\n";
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }

  unsigned char aes_key[32];
  unsigned char iv[protocol::kGcmIvLen];
  if (!crypto::random_bytes(aes_key, sizeof(aes_key)) || !crypto::random_bytes(iv, sizeof(iv))) {
    std::cerr << "Ошибка: генерация ключа/IV (RAND_bytes) не удалась.\n";
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }

  char cipher_tpl[] = "/tmp/vst_cipherXXXXXX";
  const int cfd = ::mkstemp(cipher_tpl);
  if (cfd < 0) {
    std::cerr << "Ошибка: не удалось создать временный файл для ciphertext.\n";
    std::memset(aes_key, 0, sizeof(aes_key));
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }
  ::close(cfd);
  const std::string cipher_path = cipher_tpl;
  if (!modules_tz::Encryptor::encrypt_video_to_cipher_file(aes_key, iv, file, cipher_path)) {
    std::cerr << "Ошибка: шифрование AES-256-GCM не удалось.\n";
    std::memset(aes_key, 0, sizeof(aes_key));
    std::remove(cipher_path.c_str());
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }

  const std::uint64_t cipher_file_size = fs::file_size(cipher_path);

  std::vector<unsigned char> wrapped;
  if (!crypto::rsa_oaep_sha256_wrap(wrap_pub, aes_key, sizeof(aes_key), wrapped)) {
    std::cerr << "Ошибка: RSA-OAEP обёртка ключа не удалась.\n";
    std::memset(aes_key, 0, sizeof(aes_key));
    std::remove(cipher_path.c_str());
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }

  const std::vector<unsigned char> meta_wire = vsecure::metadata::serialize(meta);
  std::vector<unsigned char> iv_vec(iv, iv + sizeof(iv));
  const auto sign_input = modules_tz::PacketBuilder::signing_blob(meta_wire, iv_vec, wrapped);

  std::vector<unsigned char> signature;
  if (!modules_tz::Signer::sign_rsa_pss_sha256(sign_priv, sign_input, signature)) {
    std::cerr << "Ошибка: формирование RSA-PSS подписи не удалось.\n";
    std::memset(aes_key, 0, sizeof(aes_key));
    std::remove(cipher_path.c_str());
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }

  vsecure::TransferPacket pkt{};
  pkt.meta = meta;
  pkt.iv = iv_vec;
  pkt.wrapped_key = std::move(wrapped);
  pkt.signature = std::move(signature);
  pkt.ciphertext.clear();

  std::vector<unsigned char> prefix;
  if (!modules_tz::PacketBuilder::build_prefix(pkt, cipher_file_size, prefix)) {
    std::cerr << "Ошибка: сборка префикса пакета не удалась.\n";
    std::memset(aes_key, 0, sizeof(aes_key));
    std::remove(cipher_path.c_str());
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }
  std::memset(aes_key, 0, sizeof(aes_key));

  if (const char* dump = std::getenv("VSECURE_DUMP_PACKET")) {
    if (*dump) {
      std::ofstream df(dump, std::ios::binary | std::ios::trunc);
      df.write(reinterpret_cast<const char*>(prefix.data()), static_cast<std::streamsize>(prefix.size()));
      if (df) {
        std::ifstream cf(cipher_path, std::ios::binary);
        char b[65536];
        while (cf.read(b, sizeof(b)) || cf.gcount() > 0)
          df.write(b, cf.gcount());
      }
      if (!df.good())
        std::cerr << "Предупреждение: не удалось записать дамп пакета (VSECURE_DUMP_PACKET).\n";
    }
  }

  const auto t0 = std::chrono::steady_clock::now();
  const int fd = modules_tz::ClientTransport::connect(host, static_cast<std::uint16_t>(port));
  if (fd < 0) {
    std::cerr << "Ошибка: сервер недоступен или неверный адрес (TCP connect).\n";
    std::remove(cipher_path.c_str());
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }

  if (!modules_tz::ClientTransport::send_framed_prefix_and_cipher_file(fd, prefix, cipher_path)) {
    std::cerr << "Ошибка: разрыв соединения при отправке пакета.\n";
    modules_tz::ClientTransport::close(fd);
    std::remove(cipher_path.c_str());
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }
  std::remove(cipher_path.c_str());

  std::uint32_t ack = 0;
  if (!modules_tz::ClientTransport::recv_ack(fd, ack)) {
    std::cerr << "Ошибка: не получен ACK от получателя (разрыв соединения).\n";
    modules_tz::ClientTransport::close(fd);
    crypto::free_pkey(sign_priv);
    crypto::free_pkey(wrap_pub);
    return 1;
  }
  modules_tz::ClientTransport::close(fd);
  crypto::free_pkey(sign_priv);
  crypto::free_pkey(wrap_pub);

  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
                      .count();

  if (ack == protocol::kAckOk) {
    std::cout << "Передача выполнена успешно за " << ms << " мс.\n";
    return 0;
  }
  if (ack == protocol::kAckBadSignature)
    std::cerr << "Ошибка на стороне получателя: подпись неверна.\n";
  else if (ack == protocol::kAckReplay)
    std::cerr << "Ошибка на стороне получателя: повторное сообщение (message_id).\n";
  else if (ack == protocol::kAckTimeSkew)
    std::cerr << "Ошибка на стороне получателя: временная метка вне допустимого окна.\n";
  else if (ack == protocol::kAckHashMismatch)
    std::cerr << "Ошибка на стороне получателя: несовпадение хэша после расшифрования.\n";
  else if (ack == protocol::kAckDecryptFailed)
    std::cerr << "Ошибка на стороне получателя: ошибка расшифрования.\n";
  else if (ack == protocol::kAckIoError)
    std::cerr << "Ошибка на стороне получателя: ошибка записи файла на диск.\n";
  else if (ack == protocol::kAckBadFormat)
    std::cerr << "Ошибка на стороне получателя: повреждённый или некорректный пакет.\n";
  else
    std::cerr << "Ошибка на стороне получателя: код " << ack << ".\n";
  return 1;
}

} // namespace vsecure
