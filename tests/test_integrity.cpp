#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

#include "vsecure/crypto.hpp"
#include "vsecure/modules_tz.hpp"

TEST_CASE("IntegrityChecker: совпадение SHA-256 с файлом") {
  char tpl[] = "/tmp/vst_int_okXXXXXX";
  const int fd = ::mkstemp(tpl);
  REQUIRE(fd >= 0);
  const char msg[] = "hello-vsecure";
  REQUIRE(::write(fd, msg, sizeof(msg) - 1) == static_cast<ssize_t>(sizeof(msg) - 1));
  ::close(fd);

  unsigned char expected[32]{};
  REQUIRE(vsecure::crypto::sha256_file(tpl, expected));
  REQUIRE(vsecure::modules_tz::IntegrityChecker::sha256_file_matches(tpl, expected));
  std::remove(tpl);
}

TEST_CASE("IntegrityChecker: несовпадение хэша (HASH_MISMATCH сценарий)") {
  char tpl[] = "/tmp/vst_int_badXXXXXX";
  const int fd = ::mkstemp(tpl);
  REQUIRE(fd >= 0);
  REQUIRE(::write(fd, "payload", 7) == 7);
  ::close(fd);

  unsigned char wrong[32]{};
  wrong[0] = 0xFF;
  REQUIRE_FALSE(vsecure::modules_tz::IntegrityChecker::sha256_file_matches(tpl, wrong));

  std::remove(tpl);
}
