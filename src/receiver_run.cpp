#include "vsecure/receiver_run.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vsecure/crypto.hpp"
#include "vsecure/event_journal.hpp"
#include "vsecure/metadata.hpp"
#include "vsecure/modules_tz.hpp"
#include "vsecure/protocol.hpp"
#include "vsecure/replay.hpp"
#include "vsecure/types.hpp"

namespace fs = std::filesystem;

namespace vsecure {

namespace {

void usage() {
  std::cerr << "Использование: vsecure_receiver --port ПОРТ --out-dir КАТАЛОГ \\\n"
                "            --sender-pub ОТПРАВИТЕЛЬ_SIGN_PUB.pem|cert.pem --recv-priv ПОЛУЧАТЕЛЬ_WRAP_PRIV.pem\n"
                "            [--seen-file ПУТЬ] (по умолчанию: КАТАЛОГ/.vsecure_seen)\n"
                "Открытый ключ отправителя: PEM SPKI или X.509 сертификат.\n";
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

std::uint64_t now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

fs::path safe_output_path(const fs::path& out_dir, const std::string& name_from_meta) {
  fs::path raw(name_from_meta);
  fs::path base = raw.filename();
  if (base.empty() || base == "." || base == "..")
    return {};
  const std::string s = base.string();
  if (s.find('/') != std::string::npos || s.find('\\') != std::string::npos)
    return {};
  return out_dir / base;
}

} // namespace

int run_secure_receiver(int argc, char** argv) {
  std::string port_str, out_dir, sender_pub, recv_priv, seen_file;
  if (!get_opt(argc, argv, "--port", port_str) || !get_opt(argc, argv, "--out-dir", out_dir) ||
      !get_opt(argc, argv, "--sender-pub", sender_pub) || !get_opt(argc, argv, "--recv-priv", recv_priv)) {
    usage();
    return 2;
  }
  (void)get_opt(argc, argv, "--seen-file", seen_file);

  const int port = std::atoi(port_str.c_str());
  if (port <= 0 || port > 65535) {
    std::cerr << "Ошибка: некорректный порт.\n";
    return 2;
  }

  fs::path outd(out_dir);
  std::error_code ec;
  fs::create_directories(outd, ec);
  if (ec || !fs::is_directory(outd)) {
    std::cerr << "Ошибка: не удалось создать или открыть каталог для сохранения.\n";
    return 1;
  }

  if (!event_journal::open(outd)) {
    std::cerr << "Предупреждение: журнал vsecure.log не открыт, события только в консоль.\n";
  }
  event_journal::line("ожидание TCP-подключения на порту " + port_str);

  if (seen_file.empty())
    seen_file = (outd / ".vsecure_seen").string();
  vsecure::replay::MessageIdStore replay_store(seen_file);

  EVP_PKEY* sign_pub = nullptr;
  EVP_PKEY* wrap_priv = nullptr;
  if (!crypto::load_public_pem(sender_pub, &sign_pub) || !sign_pub) {
    std::cerr << "Ошибка: не удалось загрузить открытый ключ/сертификат отправителя (--sender-pub).\n";
    event_journal::line("ошибка: не удалось загрузить ключ отправителя");
    event_journal::close();
    return 1;
  }
  if (!crypto::load_private_pem(recv_priv, &wrap_priv) || !wrap_priv) {
    std::cerr << "Ошибка: не удалось загрузить закрытый ключ обёртки (--recv-priv).\n";
    crypto::free_pkey(sign_pub);
    event_journal::line("ошибка: не удалось загрузить ключ обёртки");
    event_journal::close();
    return 1;
  }

  int listen_fd = -1;
  const int client = modules_tz::ServerTransport::accept_one_client(static_cast<std::uint16_t>(port), listen_fd);
  if (client < 0) {
    std::cerr << "Ошибка: не удалось открыть порт или принять соединение.\n";
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("ошибка: accept/bind");
    event_journal::close();
    return 1;
  }
  modules_tz::ServerTransport::close(listen_fd);
  listen_fd = -1;
  event_journal::line("TCP-соединение принято");

  char pkt_tpl[] = "/tmp/vst_pktXXXXXX";
  const int pfd = ::mkstemp(pkt_tpl);
  if (pfd < 0) {
    std::cerr << "Ошибка: не удалось создать временный файл для пакета.\n";
    modules_tz::ServerTransport::send_ack(client, protocol::kAckIoError);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::close();
    return 1;
  }
  ::close(pfd);
  const std::string pkt_path = pkt_tpl;

  std::uint64_t body_len = 0;
  if (!modules_tz::ServerTransport::recv_framed_to_file(client, pkt_path, body_len)) {
    std::cerr << "Ошибка: разрыв соединения или пустой поток при приёме пакета.\n";
    modules_tz::ServerTransport::send_ack(client, protocol::kAckConnectionError);
    modules_tz::ServerTransport::close(client);
    std::remove(pkt_path.c_str());
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("ошибка: приём фрейма");
    event_journal::close();
    return 1;
  }

  const int mfd = ::open(pkt_path.c_str(), O_RDONLY);
  if (mfd < 0) {
    std::cerr << "Ошибка: не удалось открыть временный пакет для разбора.\n";
    modules_tz::ServerTransport::send_ack(client, protocol::kAckIoError);
    modules_tz::ServerTransport::close(client);
    std::remove(pkt_path.c_str());
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::close();
    return 1;
  }
  struct stat st {};
  if (::fstat(mfd, &st) != 0 || st.st_size <= 0) {
    ::close(mfd);
    modules_tz::ServerTransport::send_ack(client, protocol::kAckBadFormat);
    modules_tz::ServerTransport::close(client);
    std::remove(pkt_path.c_str());
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::close();
    return 1;
  }
  void* mm = ::mmap(nullptr, static_cast<std::size_t>(st.st_size), PROT_READ, MAP_PRIVATE, mfd, 0);
  ::close(mfd);
  if (mm == MAP_FAILED) {
    std::cerr << "Ошибка: mmap пакета не удался.\n";
    modules_tz::ServerTransport::send_ack(client, protocol::kAckIoError);
    modules_tz::ServerTransport::close(client);
    std::remove(pkt_path.c_str());
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::close();
    return 1;
  }
  const auto unmap = [&]() { ::munmap(mm, static_cast<std::size_t>(st.st_size)); };
  const auto cleanup_pkt = [&]() {
    unmap();
    std::remove(pkt_path.c_str());
  };

  TransferPacket pkt;
  if (!modules_tz::PacketParser::parse_file_transfer(static_cast<const unsigned char*>(mm),
                                                      static_cast<std::size_t>(st.st_size), pkt)) {
    std::cerr << "Ошибка: повреждённый или некорректный пакет (формат).\n";
    cleanup_pkt();
    modules_tz::ServerTransport::send_ack(client, protocol::kAckBadFormat);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("ошибка: формат пакета");
    event_journal::close();
    return 1;
  }
  cleanup_pkt();
  event_journal::line("пакет разобран, метаданные получены");

  const std::uint64_t tnow = now_ms();
  if (!vsecure::replay::MessageIdStore::timestamp_ok(tnow, pkt.meta.unix_timestamp_ms)) {
    std::cerr << "Событие: временная метка вне допустимого окна (возможная неактуальность).\n";
    modules_tz::ServerTransport::send_ack(client, protocol::kAckTimeSkew);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("отклонено: временная метка");
    event_journal::close();
    return 1;
  }

  if (replay_store.is_replay(pkt.meta.message_id)) {
    std::cerr << "Событие: повторное сообщение (message_id).\n";
    modules_tz::ServerTransport::send_ack(client, protocol::kAckReplay);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("отклонено: повтор message_id");
    event_journal::close();
    return 1;
  }

  const std::vector<unsigned char> meta_wire = vsecure::metadata::serialize(pkt.meta);
  const auto sign_input = modules_tz::PacketBuilder::signing_blob(meta_wire, pkt.iv, pkt.wrapped_key);
  if (!modules_tz::Verifier::rsa_pss_sha256_verify(sign_pub, sign_input.data(), sign_input.size(), pkt.signature.data(),
                                                   pkt.signature.size())) {
    std::cerr << "Ошибка: подпись отправителя неверна.\n";
    modules_tz::ServerTransport::send_ack(client, protocol::kAckBadSignature);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("отклонено: подпись неверна");
    event_journal::close();
    return 1;
  }
  event_journal::line("подпись RSA-PSS проверена успешно");

  std::vector<unsigned char> aes_key;
  if (!crypto::rsa_oaep_sha256_unwrap(wrap_priv, pkt.wrapped_key.data(), pkt.wrapped_key.size(), aes_key)) {
    std::cerr << "Ошибка: не удалось извлечь симметричный ключ (RSA-OAEP).\n";
    modules_tz::ServerTransport::send_ack(client, protocol::kAckDecryptFailed);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("ошибка: RSA-OAEP unwrap");
    event_journal::close();
    return 1;
  }

  const fs::path out_path = safe_output_path(outd, pkt.meta.filename_utf8);
  if (out_path.empty()) {
    std::cerr << "Ошибка: некорректное имя файла в метаданных.\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    modules_tz::ServerTransport::send_ack(client, protocol::kAckBadFormat);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("ошибка: имя файла");
    event_journal::close();
    return 1;
  }

  const std::string tmp_plain = out_path.string() + ".vst.tmp";
  if (!modules_tz::Decryptor::aes256_gcm_to_file(aes_key.data(), pkt.iv.data(), pkt.ciphertext.data(),
                                                pkt.ciphertext.size(), tmp_plain)) {
    std::cerr << "Ошибка: расшифрование AES-256-GCM не удалось (повреждение или подмена данных).\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    std::remove(tmp_plain.c_str());
    modules_tz::ServerTransport::send_ack(client, protocol::kAckDecryptFailed);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("ошибка: расшифрование GCM");
    event_journal::close();
    return 1;
  }

  if (fs::file_size(tmp_plain) != pkt.meta.original_size) {
    std::cerr << "Ошибка: размер расшифрованных данных не совпадает с метаданными.\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    std::remove(tmp_plain.c_str());
    modules_tz::ServerTransport::send_ack(client, protocol::kAckHashMismatch);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("ошибка: размер файла");
    event_journal::close();
    return 1;
  }

  if (!modules_tz::IntegrityChecker::sha256_file_matches(tmp_plain, pkt.meta.sha256_plaintext)) {
    std::cerr << "Ошибка: целостность нарушена — хэш SHA-256 не совпадает.\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    std::remove(tmp_plain.c_str());
    modules_tz::ServerTransport::send_ack(client, protocol::kAckHashMismatch);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("отклонено: хэш SHA-256");
    event_journal::close();
    return 1;
  }
  event_journal::line("целостность SHA-256 подтверждена");

  if (!modules_tz::FileWriter::commit_temp_file(tmp_plain, out_path.string())) {
    std::cerr << "Ошибка: не удалось записать восстановленный файл на диск.\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    std::remove(tmp_plain.c_str());
    modules_tz::ServerTransport::send_ack(client, protocol::kAckIoError);
    modules_tz::ServerTransport::close(client);
    crypto::free_pkey(sign_pub);
    crypto::free_pkey(wrap_priv);
    event_journal::line("ошибка: rename/запись файла");
    event_journal::close();
    return 1;
  }

  std::memset(aes_key.data(), 0, aes_key.size());
  replay_store.commit(pkt.meta.message_id);

  modules_tz::ServerTransport::send_ack(client, protocol::kAckOk);
  modules_tz::ServerTransport::close(client);
  crypto::free_pkey(sign_pub);
  crypto::free_pkey(wrap_priv);

  std::cout << "Файл успешно получен и сохранён: " << out_path << "\n";
  std::cout << "Проверки: подпись верна; целостность SHA-256 подтверждена; сообщение новое.\n";
  event_journal::line("файл успешно сохранён: " + out_path.string());
  event_journal::close();
  return 0;
}

} // namespace vsecure
