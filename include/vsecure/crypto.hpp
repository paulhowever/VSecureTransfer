#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <openssl/evp.h>

namespace vsecure::crypto {

class Sha256Stream {
public:
  Sha256Stream();
  ~Sha256Stream();
  Sha256Stream(const Sha256Stream&) = delete;
  Sha256Stream& operator=(const Sha256Stream&) = delete;

  /** false если контекст EVP не инициализирован. */
  bool update(const void* data, std::size_t len);
  /** false при сбое инициализации EVP или DigestFinal; out обнуляется. */
  bool final(unsigned char out[32]);

private:
  EVP_MD_CTX* ctx_ = nullptr;
};

/** SHA-256 всего файла (потоково). */
bool sha256_file(const std::string& path, unsigned char out[32]);

/** AES-256-GCM: out = ciphertext || tag (16). */
bool aes256_gcm_encrypt(const unsigned char* key32, const unsigned char* iv12, const unsigned char* plain,
                        std::size_t plain_len, std::vector<unsigned char>& out_cipher_with_tag);

/** Потоковое чтение файла, шифрование AES-256-GCM (tag в конце out). */
bool aes256_gcm_encrypt_file_path(const unsigned char* key32, const unsigned char* iv12,
                                  const std::string& path, std::vector<unsigned char>& out_cipher_with_tag);

/** Шифрование в файл (без хранения всего ciphertext в RAM). */
bool aes256_gcm_encrypt_file_path_to_file(const unsigned char* key32, const unsigned char* iv12,
                                         const std::string& in_path, const std::string& out_cipher_path);

bool aes256_gcm_decrypt(const unsigned char* key32, const unsigned char* iv12,
                        const unsigned char* cipher_with_tag, std::size_t len,
                        std::vector<unsigned char>& out_plain);

/** Расшифрование в файл (потоково, без std::vector всего plaintext). */
bool aes256_gcm_decrypt_to_file(const unsigned char* key32, const unsigned char* iv12,
                                const unsigned char* cipher_with_tag, std::size_t len,
                                const std::string& out_plain_path);

bool load_private_pem(const std::string& path, EVP_PKEY** out);

/** PEM SubjectPublicKeyInfo или PEM X.509 сертификат (извлекается открытый ключ). */
bool load_public_pem(const std::string& path, EVP_PKEY** out);

bool rsa_oaep_sha256_wrap(EVP_PKEY* wrap_pub, const unsigned char* aes_key32, std::size_t aes_key_len,
                          std::vector<unsigned char>& out_wrapped);

bool rsa_oaep_sha256_unwrap(EVP_PKEY* wrap_priv, const unsigned char* wrapped, std::size_t wrapped_len,
                            std::vector<unsigned char>& out_aes_key);

/** Подпись RSA-PSS SHA-256 над message. */
bool rsa_pss_sha256_sign(EVP_PKEY* sign_priv, const unsigned char* msg, std::size_t msg_len,
                         std::vector<unsigned char>& out_sig);

bool rsa_pss_sha256_verify(EVP_PKEY* sign_pub, const unsigned char* msg, std::size_t msg_len,
                           const unsigned char* sig, std::size_t sig_len);

void free_pkey(EVP_PKEY* p);

/** false при ошибке RAND_bytes (буфер не трогаем). */
bool random_bytes(unsigned char* buf, std::size_t len);

} // namespace vsecure::crypto
