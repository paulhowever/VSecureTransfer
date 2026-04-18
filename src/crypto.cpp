#include "vsecure/crypto.hpp"

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace vsecure::crypto {

Sha256Stream::Sha256Stream() {
  ctx_ = EVP_MD_CTX_new();
  if (!ctx_ || EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx_);
    ctx_ = nullptr;
  }
}

Sha256Stream::~Sha256Stream() { EVP_MD_CTX_free(ctx_); }

bool Sha256Stream::update(const void* data, std::size_t len) {
  if (!ctx_)
    return false;
  return EVP_DigestUpdate(ctx_, data, len) == 1;
}

bool Sha256Stream::final(unsigned char out[32]) {
  unsigned int w = 0;
  if (!ctx_ || EVP_DigestFinal_ex(ctx_, out, &w) != 1 || w != 32) {
    std::memset(out, 0, 32);
    return false;
  }
  return true;
}

bool sha256_file(const std::string& path, unsigned char out[32]) {
  Sha256Stream hasher;
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return false;
  char buf[65536];
  while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
    if (!hasher.update(buf, static_cast<std::size_t>(in.gcount())))
      return false;
  }
  return hasher.final(out);
}

static bool evp_encrypt_gcm_core(const unsigned char* key32, const unsigned char* iv12,
                                 const unsigned char* plain, std::size_t plain_len,
                                 std::vector<unsigned char>& out) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return false;
  bool ok = false;
  int len = 0;
  out.assign(plain_len + 16, 0);
  do {
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key32, iv12) != 1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
      break;
    if (EVP_EncryptUpdate(ctx, out.data(), &len, plain, static_cast<int>(plain_len)) != 1)
      break;
    out.resize(static_cast<std::size_t>(len));
    int len2 = 0;
    if (EVP_EncryptFinal_ex(ctx, nullptr, &len2) != 1)
      break;
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
      break;
    out.insert(out.end(), tag, tag + 16);
    ok = true;
  } while (false);
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

bool aes256_gcm_encrypt(const unsigned char* key32, const unsigned char* iv12, const unsigned char* plain,
                        std::size_t plain_len, std::vector<unsigned char>& out_cipher_with_tag) {
  return evp_encrypt_gcm_core(key32, iv12, plain, plain_len, out_cipher_with_tag);
}

static bool aes256_gcm_encrypt_streams(const unsigned char* key32, const unsigned char* iv12, FILE* in, FILE* out) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx || !in || !out)
    return false;
  bool ok = false;
  unsigned char inbuf[65536];
  do {
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key32, iv12) != 1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
      break;
    for (;;) {
      const std::size_t n = std::fread(inbuf, 1, sizeof(inbuf), in);
      if (n == 0 && ferror(in))
        goto done;
      if (n == 0)
        break;
      unsigned char obuf[sizeof(inbuf) + EVP_MAX_BLOCK_LENGTH];
      int ol = 0;
      if (EVP_EncryptUpdate(ctx, obuf, &ol, inbuf, static_cast<int>(n)) != 1)
        goto done;
      if (ol > 0 && std::fwrite(obuf, 1, static_cast<std::size_t>(ol), out) != static_cast<std::size_t>(ol))
        goto done;
      if (n < sizeof(inbuf))
        break;
    }
    unsigned char finbuf[32];
    int fl = 0;
    if (EVP_EncryptFinal_ex(ctx, finbuf, &fl) != 1)
      goto done;
    if (fl > 0 && std::fwrite(finbuf, 1, static_cast<std::size_t>(fl), out) != static_cast<std::size_t>(fl))
      goto done;
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
      goto done;
    if (std::fwrite(tag, 1, 16, out) != 16)
      goto done;
    ok = true;
  } while (false);
done:
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

bool aes256_gcm_encrypt_file_path(const unsigned char* key32, const unsigned char* iv12,
                                  const std::string& path, std::vector<unsigned char>& out_cipher_with_tag) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f)
    return false;
  bool ok = false;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    std::fclose(f);
    return false;
  }
  out_cipher_with_tag.clear();
  unsigned char inbuf[65536];
  do {
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key32, iv12) != 1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
      break;
    for (;;) {
      const std::size_t n = std::fread(inbuf, 1, sizeof(inbuf), f);
      if (n == 0 && ferror(f)) {
        out_cipher_with_tag.clear();
        goto done;
      }
      if (n == 0)
        break;
      unsigned char obuf[sizeof(inbuf) + EVP_MAX_BLOCK_LENGTH];
      int ol = 0;
      if (EVP_EncryptUpdate(ctx, obuf, &ol, inbuf, static_cast<int>(n)) != 1) {
        out_cipher_with_tag.clear();
        goto done;
      }
      out_cipher_with_tag.insert(out_cipher_with_tag.end(), obuf, obuf + ol);
      if (n < sizeof(inbuf))
        break;
    }
    unsigned char finbuf[32];
    int fl = 0;
    if (EVP_EncryptFinal_ex(ctx, finbuf, &fl) != 1) {
      out_cipher_with_tag.clear();
      break;
    }
    if (fl > 0)
      out_cipher_with_tag.insert(out_cipher_with_tag.end(), finbuf, finbuf + fl);
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
      out_cipher_with_tag.clear();
      break;
    }
    out_cipher_with_tag.insert(out_cipher_with_tag.end(), tag, tag + 16);
    ok = true;
  } while (false);
done:
  EVP_CIPHER_CTX_free(ctx);
  std::fclose(f);
  return ok;
}

bool aes256_gcm_encrypt_file_path_to_file(const unsigned char* key32, const unsigned char* iv12,
                                          const std::string& in_path, const std::string& out_cipher_path) {
  FILE* in = std::fopen(in_path.c_str(), "rb");
  if (!in)
    return false;
  FILE* out = std::fopen(out_cipher_path.c_str(), "wb");
  if (!out) {
    std::fclose(in);
    return false;
  }
  const bool ok = aes256_gcm_encrypt_streams(key32, iv12, in, out);
  std::fclose(in);
  std::fclose(out);
  if (!ok)
    std::remove(out_cipher_path.c_str());
  return ok;
}

bool aes256_gcm_decrypt(const unsigned char* key32, const unsigned char* iv12,
                        const unsigned char* cipher_with_tag, std::size_t len,
                        std::vector<unsigned char>& out_plain) {
  if (len < 16)
    return false;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return false;
  bool ok = false;
  const std::size_t ct_len = len - 16;
  const unsigned char* tag = cipher_with_tag + ct_len;
  out_plain.assign(ct_len, 0);
  int outl = 0;
  do {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key32, iv12) != 1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
      break;
    if (EVP_DecryptUpdate(ctx, out_plain.data(), &outl, cipher_with_tag, static_cast<int>(ct_len)) != 1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag)) != 1)
      break;
    int fin = 0;
    if (EVP_DecryptFinal_ex(ctx, out_plain.data() + outl, &fin) != 1)
      break;
    out_plain.resize(static_cast<std::size_t>(outl));
    ok = true;
  } while (false);
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

bool aes256_gcm_decrypt_to_file(const unsigned char* key32, const unsigned char* iv12,
                                const unsigned char* cipher_with_tag, std::size_t len,
                                const std::string& out_plain_path) {
  if (len < 16)
    return false;
  FILE* out = std::fopen(out_plain_path.c_str(), "wb");
  if (!out)
    return false;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    std::fclose(out);
    return false;
  }
  bool ok = false;
  const std::size_t ct_len = len - 16;
  const unsigned char* tag = cipher_with_tag + ct_len;
  do {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key32, iv12) != 1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
      break;
    std::size_t off = 0;
    while (off < ct_len) {
      const int chunk = static_cast<int>(std::min<std::size_t>(65536, ct_len - off));
      unsigned char obuf[65536 + EVP_MAX_BLOCK_LENGTH];
      int ol = 0;
      if (EVP_DecryptUpdate(ctx, obuf, &ol, cipher_with_tag + off, chunk) != 1)
        goto fail;
      if (ol > 0 && std::fwrite(obuf, 1, static_cast<std::size_t>(ol), out) != static_cast<std::size_t>(ol))
        goto fail;
      off += static_cast<std::size_t>(chunk);
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag)) != 1)
      break;
    unsigned char finbuf[256];
    int fl = 0;
    if (EVP_DecryptFinal_ex(ctx, finbuf, &fl) != 1)
      break;
    if (fl > 0 && std::fwrite(finbuf, 1, static_cast<std::size_t>(fl), out) != static_cast<std::size_t>(fl))
      break;
    ok = true;
  } while (false);
fail:
  EVP_CIPHER_CTX_free(ctx);
  std::fclose(out);
  if (!ok)
    std::remove(out_plain_path.c_str());
  return ok;
}

bool load_private_pem(const std::string& path, EVP_PKEY** out) {
  *out = nullptr;
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f)
    return false;
  EVP_PKEY* p = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
  std::fclose(f);
  *out = p;
  return p != nullptr;
}

bool load_public_pem(const std::string& path, EVP_PKEY** out) {
  *out = nullptr;
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f)
    return false;
  EVP_PKEY* p = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
  if (p) {
    std::fclose(f);
    *out = p;
    return true;
  }
  std::rewind(f);
  X509* x = PEM_read_X509(f, nullptr, nullptr, nullptr);
  std::fclose(f);
  if (!x)
    return false;
  p = X509_get_pubkey(x);
  X509_free(x);
  *out = p;
  return p != nullptr;
}

bool rsa_oaep_sha256_wrap(EVP_PKEY* wrap_pub, const unsigned char* aes_key32, std::size_t aes_key_len,
                          std::vector<unsigned char>& out_wrapped) {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(wrap_pub, nullptr);
  if (!pctx)
    return false;
  bool ok = false;
  std::size_t outlen = 0;
  do {
    if (EVP_PKEY_encrypt_init(pctx) <= 0)
      break;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0)
      break;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0)
      break;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0)
      break;
    if (EVP_PKEY_encrypt(pctx, nullptr, &outlen, aes_key32, aes_key_len) <= 0)
      break;
    out_wrapped.resize(outlen);
    if (EVP_PKEY_encrypt(pctx, out_wrapped.data(), &outlen, aes_key32, aes_key_len) <= 0) {
      out_wrapped.clear();
      break;
    }
    out_wrapped.resize(outlen);
    ok = true;
  } while (false);
  EVP_PKEY_CTX_free(pctx);
  return ok;
}

bool rsa_oaep_sha256_unwrap(EVP_PKEY* wrap_priv, const unsigned char* wrapped, std::size_t wrapped_len,
                            std::vector<unsigned char>& out_aes_key) {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(wrap_priv, nullptr);
  if (!pctx)
    return false;
  bool ok = false;
  std::size_t outlen = 0;
  do {
    if (EVP_PKEY_decrypt_init(pctx) <= 0)
      break;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0)
      break;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0)
      break;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0)
      break;
    if (EVP_PKEY_decrypt(pctx, nullptr, &outlen, wrapped, wrapped_len) <= 0)
      break;
    out_aes_key.resize(outlen);
    if (EVP_PKEY_decrypt(pctx, out_aes_key.data(), &outlen, wrapped, wrapped_len) <= 0) {
      out_aes_key.clear();
      break;
    }
    out_aes_key.resize(outlen);
    ok = (out_aes_key.size() == 32);
  } while (false);
  EVP_PKEY_CTX_free(pctx);
  return ok;
}

bool rsa_pss_sha256_sign(EVP_PKEY* sign_priv, const unsigned char* msg, std::size_t msg_len,
                         std::vector<unsigned char>& out_sig) {
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return false;
  bool ok = false;
  EVP_PKEY_CTX* pctx = nullptr;
  std::size_t siglen = 0;
  do {
    if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), nullptr, sign_priv) != 1)
      break;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
      break;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
      break;
    if (EVP_DigestSignUpdate(mdctx, msg, msg_len) != 1)
      break;
    if (EVP_DigestSignFinal(mdctx, nullptr, &siglen) != 1)
      break;
    out_sig.resize(siglen);
    if (EVP_DigestSignFinal(mdctx, out_sig.data(), &siglen) != 1) {
      out_sig.clear();
      break;
    }
    out_sig.resize(siglen);
    ok = true;
  } while (false);
  EVP_MD_CTX_free(mdctx);
  return ok;
}

bool rsa_pss_sha256_verify(EVP_PKEY* sign_pub, const unsigned char* msg, std::size_t msg_len,
                           const unsigned char* sig, std::size_t sig_len) {
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return false;
  bool ok = false;
  EVP_PKEY_CTX* pctx = nullptr;
  do {
    if (EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), nullptr, sign_pub) != 1)
      break;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
      break;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
      break;
    if (EVP_DigestVerifyUpdate(mdctx, msg, msg_len) != 1)
      break;
    if (EVP_DigestVerifyFinal(mdctx, sig, sig_len) != 1)
      break;
    ok = true;
  } while (false);
  EVP_MD_CTX_free(mdctx);
  return ok;
}

void free_pkey(EVP_PKEY* p) { EVP_PKEY_free(p); }

bool random_bytes(unsigned char* buf, std::size_t len) { return RAND_bytes(buf, static_cast<int>(len)) == 1; }

} // namespace vsecure::crypto
