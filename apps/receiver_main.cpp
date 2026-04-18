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
#include "vsecure/replay.hpp"
#include "vsecure/tcp.hpp"
#include "vsecure/types.hpp"

namespace fs = std::filesystem;

static void usage() {
  std::cerr << "Использование: vsecure_receiver --port ПОРТ --out-dir КАТАЛОГ \\\n"
                "            --sender-pub ОТПРАВИТЕЛЬ_SIGN_PUB.pem --recv-priv ПОЛУЧАТЕЛЬ_WRAP_PRIV.pem\n"
                "            [--seen-file ПУТЬ] (по умолчанию: КАТАЛОГ/.vsecure_seen)\n";
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

static std::uint64_t now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

/** Безопасное имя для записи в out_dir (только basename, без путей). */
static fs::path safe_output_path(const fs::path& out_dir, const std::string& name_from_meta) {
  fs::path raw(name_from_meta);
  fs::path base = raw.filename();
  if (base.empty() || base == "." || base == "..")
    return {};
  const std::string s = base.string();
  if (s.find('/') != std::string::npos || s.find('\\') != std::string::npos)
    return {};
  return out_dir / base;
}

int main(int argc, char** argv) {
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

  if (seen_file.empty())
    seen_file = (outd / ".vsecure_seen").string();
  vsecure::replay::MessageIdStore replay_store(seen_file);

  EVP_PKEY* sign_pub = nullptr;
  EVP_PKEY* wrap_priv = nullptr;
  if (!vsecure::crypto::load_public_pem(sender_pub, &sign_pub) || !sign_pub) {
    std::cerr << "Ошибка: не удалось загрузить открытый ключ отправителя (--sender-pub).\n";
    return 1;
  }
  if (!vsecure::crypto::load_private_pem(recv_priv, &wrap_priv) || !wrap_priv) {
    std::cerr << "Ошибка: не удалось загрузить закрытый ключ обёртки (--recv-priv).\n";
    vsecure::crypto::free_pkey(sign_pub);
    return 1;
  }

  int listen_fd = -1;
  const int client = vsecure::tcp::accept_one(static_cast<std::uint16_t>(port), listen_fd);
  if (client < 0) {
    std::cerr << "Ошибка: не удалось открыть порт или принять соединение.\n";
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }
  vsecure::tcp::close_fd(listen_fd);
  listen_fd = -1;

  std::vector<unsigned char> wire;
  if (!vsecure::tcp::recv_framed(client, wire)) {
    std::cerr << "Ошибка: разрыв соединения или пустой поток при приёме пакета.\n";
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckConnectionError);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  vsecure::TransferPacket pkt;
  if (!vsecure::packet::decode_file_transfer(wire.data(), wire.size(), pkt)) {
    std::cerr << "Ошибка: повреждённый или некорректный пакет (формат).\n";
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckBadFormat);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  const std::uint64_t tnow = now_ms();
  if (!vsecure::replay::MessageIdStore::timestamp_ok(tnow, pkt.meta.unix_timestamp_ms)) {
    std::cerr << "Событие: временная метка вне допустимого окна (возможная неактуальность).\n";
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckTimeSkew);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  if (replay_store.is_replay(pkt.meta.message_id)) {
    std::cerr << "Событие: повторное сообщение (message_id).\n";
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckReplay);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  const std::vector<unsigned char> meta_wire = vsecure::metadata::serialize(pkt.meta);
  const auto sign_input = vsecure::packet::signing_blob(meta_wire, pkt.iv, pkt.wrapped_key);
  if (!vsecure::crypto::rsa_pss_sha256_verify(sign_pub, sign_input.data(), sign_input.size(), pkt.signature.data(),
                                             pkt.signature.size())) {
    std::cerr << "Ошибка: подпись отправителя неверна.\n";
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckBadSignature);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  std::vector<unsigned char> aes_key;
  if (!vsecure::crypto::rsa_oaep_sha256_unwrap(wrap_priv, pkt.wrapped_key.data(), pkt.wrapped_key.size(), aes_key)) {
    std::cerr << "Ошибка: не удалось извлечь симметричный ключ (RSA-OAEP).\n";
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckDecryptFailed);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  std::vector<unsigned char> plain;
  if (!vsecure::crypto::aes256_gcm_decrypt(aes_key.data(), pkt.iv.data(), pkt.ciphertext.data(), pkt.ciphertext.size(),
                                          plain)) {
    std::cerr << "Ошибка: расшифрование AES-256-GCM не удалось (повреждение или подмена данных).\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckDecryptFailed);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  if (plain.size() != pkt.meta.original_size) {
    std::cerr << "Ошибка: размер расшифрованных данных не совпадает с метаданными.\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckHashMismatch);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  vsecure::crypto::Sha256Stream h2;
  h2.update(plain.data(), plain.size());
  unsigned char recomputed[32];
  if (!h2.final(recomputed)) {
    std::cerr << "Ошибка: не удалось завершить пересчёт SHA-256.\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckBadFormat);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }
  if (std::memcmp(recomputed, pkt.meta.sha256_plaintext, 32) != 0) {
    std::cerr << "Ошибка: целостность нарушена — хэш SHA-256 не совпадает.\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckHashMismatch);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  const fs::path out_path = safe_output_path(outd, pkt.meta.filename_utf8);
  if (out_path.empty()) {
    std::cerr << "Ошибка: некорректное имя файла в метаданных.\n";
    std::memset(aes_key.data(), 0, aes_key.size());
    vsecure::tcp::send_ack(client, vsecure::protocol::kAckBadFormat);
    vsecure::tcp::close_fd(client);
    vsecure::crypto::free_pkey(sign_pub);
    vsecure::crypto::free_pkey(wrap_priv);
    return 1;
  }

  {
    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out || !out.write(reinterpret_cast<const char*>(plain.data()), static_cast<std::streamsize>(plain.size()))) {
      std::cerr << "Ошибка: не удалось записать восстановленный файл на диск.\n";
      std::memset(aes_key.data(), 0, aes_key.size());
      vsecure::tcp::send_ack(client, vsecure::protocol::kAckIoError);
      vsecure::tcp::close_fd(client);
      vsecure::crypto::free_pkey(sign_pub);
      vsecure::crypto::free_pkey(wrap_priv);
      return 1;
    }
  }

  std::memset(aes_key.data(), 0, aes_key.size());
  replay_store.commit(pkt.meta.message_id);

  vsecure::tcp::send_ack(client, vsecure::protocol::kAckOk);
  vsecure::tcp::close_fd(client);
  vsecure::crypto::free_pkey(sign_pub);
  vsecure::crypto::free_pkey(wrap_priv);

  std::cout << "Файл успешно получен и сохранён: " << out_path << "\n";
  std::cout << "Проверки: подпись верна; целостность SHA-256 подтверждена; сообщение новое.\n";
  return 0;
}
