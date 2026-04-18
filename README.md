# VSecureTransfer

Защищённая передача одного видеофайла по TCP: **конфиденциальность** (AES-256-GCM), **целостность** (SHA-256 исходника + AEAD), **аутентичность** (RSA-PSS подпись канонических полей и RSA-OAEP обёртка сеансового ключа). Проект учебный / демонстрационный, без PKI и без потокового стриминга.

**Для заказчика / приёмки:** одностраничная сопроводительная записка — [`docs/HANDOFF.md`](docs/HANDOFF.md) (ключи, порты, порядок запуска, Windows через Docker/WSL2).

[![CI](https://github.com/paulhowever/VSecureTransfer/actions/workflows/ci.yml/badge.svg)](https://github.com/paulhowever/VSecureTransfer/actions/workflows/ci.yml)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![OpenSSL 3](https://img.shields.io/badge/OpenSSL-3.x-green.svg)](https://www.openssl.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Возможности

| Свойство | Реализация |
|----------|------------|
| Шифрование полезной нагрузки | AES-256-GCM (IV 12 байт, tag 16 байт) |
| Хэш исходного файла | SHA-256 в метаданных, пересчёт после расшифрования |
| Сеансовый ключ | Случайные 32 байта, упаковка **RSA-OAEP** (SHA-256 + MGF1-SHA256) открытым ключом **получателя** |
| Подпись отправителя | **RSA-PSS** (SHA-256, salt = digest length) над `meta ‖ IV ‖ wrapped_key` |
| Транспорт | TCP: `uint64` big-endian длина кадра, затем тело; ответ **ACK** 8 байт (`VACK` + код); **подключение через `getaddrinfo`** (IPv4/IPv6), сервер по возможности слушает **IPv6 dual-stack** (`IPV6_V6ONLY=0`) с запасным IPv4 |
| Анти-replay | Окно времени ±300 с по `unix_timestamp_ms` и учёт `message_id` (16 байт) в файле `--seen-file` |

Поддерживаемые расширения имён файлов на отправителе: `.mp4`, `.avi`, `.mkv`.

## Архитектура

```mermaid
sequenceDiagram
  participant S as Sender
  participant T as TCP
  participant R as Receiver
  S->>S: SHA256 plaintext
  S->>S: AES256GCM encrypt
  S->>S: RSAOAEP wrap key
  S->>S: RSAPSS sign meta IV wrapped
  S->>T: framed packet
  T->>R: framed packet
  R->>R: time window message_id
  R->>R: verify unwrap decrypt hash
  R->>T: ACK
  T->>S: ACK
```

Спецификация бинарного протокола v1 описана в комментариях к [`include/vsecure/protocol.hpp`](include/vsecure/protocol.hpp).

## Сборка

### Зависимости

- Компилятор с **C++17** (**Clang** или **GCC**) для **нативной** сборки на **Linux** и **macOS**.
- **OpenSSL 3.x** (libcrypto; заголовки `openssl/evp.h`, `openssl/pem.h`, …).

### Платформы и Windows

| ОС | Как работать |
|----|----------------|
| **Linux** | Нативно: `cmake` или `make`, см. ниже. |
| **macOS** | Нативно: Homebrew OpenSSL, при необходимости `brew install cmake`. |
| **Windows** | Код использует POSIX (сокеты, `poll`, `mmap`, временные файлы). **Нативная сборка MSVC в репозитории не поддерживается.** Удобные варианты: **Docker Desktop** (Linux-контейнер) или **WSL2 (Ubuntu)** — те же команды, что на Linux. Подробности в [`docs/HANDOFF.md`](docs/HANDOFF.md). |

**Docker (один раз собрать образ, затем приёмка внутри контейнера):**

```bash
docker build -t vsecure-transfer .
docker run --rm -it vsecure-transfer bash -lc 'cd /app && ./scripts/gen_keys.sh && ./scripts/qa_full.sh'
```

Образ содержит `build/vsecure_sender` и `build/vsecure_receiver` в `PATH`; ключи создаются внутри запуска (каталог `keys/` в контейнере, не на хосте). Тот же сценарий гоняется в CI (**job `docker-qa`** в [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

### Вариант A: Makefile (macOS / Homebrew)

```bash
export OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3   # при необходимости
make -j
```

### Вариант B: CMake

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
# исполняемые файлы: build/vsecure_sender, build/vsecure_receiver
```

На macOS `CMakeLists.txt` пытается подставить `OPENSSL_ROOT_DIR` из типичных путей Homebrew.

### Если в терминале `zsh: command not found: cmake`

**Юнит-тесты** (Catch2, `ctest`) собираются только через CMake. На macOS:

```bash
brew install cmake
```

Часто нужно, чтобы в сессии был путь Homebrew, например в `~/.zprofile`:

```bash
eval "$(/opt/homebrew/bin/brew shellenv)"
```

Пока CMake не установлен, можно собрать **`make -j`** и запустить **`./scripts/qa_full.sh`** из корня репозитория — интеграционные сценарии выполнятся, а `ctest` будет пропущен (нет `build/vsecure_unit_tests`).

Если команда **`cd build`** завершилась ошибкой (каталог не создался), не подряд выполняйте **`cd .. && ./scripts/qa_full.sh`**: вы можете оказаться в родительском каталоге (`maxik_WW`), где нет `scripts/qa_full.sh`. Сначала снова перейдите в **`VSecureTransfer`**, затем запускайте скрипт.

## Ключи

Сгенерируйте **две** пары RSA (отдельно для подписи отправителя и для обёртки AES у получателя):

```bash
./scripts/gen_keys.sh
```

Появятся файлы в `keys/` (каталог в `.gitignore` — **не коммитьте** ключи):

| Файл | Кто использует |
|------|----------------|
| `sender_sign_priv.pem` | Отправитель (подпись) |
| `sender_sign_pub.pem` | Получатель (проверка подписи) |
| `receiver_wrap_pub.pem` | Отправитель (OAEP-wrap AES-ключа) |
| `receiver_wrap_priv.pem` | Получатель (OAEP-unwrap) |

Эквивалент вручную через `openssl genpkey` / `openssl pkey` описан в [`scripts/gen_keys.sh`](scripts/gen_keys.sh).

## Запуск

**Терминал 1 — получатель:**

```bash
./vsecure_receiver --port 9000 --out-dir ./out \
  --sender-pub keys/sender_sign_pub.pem \
  --recv-priv keys/receiver_wrap_priv.pem
```

**Терминал 2 — отправитель:**

```bash
./vsecure_sender --file ./video.mp4 --host 127.0.0.1 --port 9000 \
  --sign-key keys/sender_sign_priv.pem \
  --recv-pub keys/receiver_wrap_pub.pem
```

Для имени хоста (в т.ч. `localhost` при записи `::1` в `/etc/hosts`) отправитель резолвит адреса через **`getaddrinfo`**, предпочитая **IPv6**, затем IPv4.

Опционально: `--seen-file ПУТЬ` у получателя (по умолчанию `./out/.vsecure_seen`).

### Отладка / QA

Если задана переменная окружения `VSECURE_DUMP_PACKET=/path/to/file.bin`, отправитель дополнительно сохранит **сырое** тело пакета (без TCP-длины) — используется в [`scripts/test_replay_packet.sh`](scripts/test_replay_packet.sh).

## CI

На каждый push / PR в `main` запускается [GitHub Actions](.github/workflows/ci.yml): `ubuntu-latest`, пакеты `build-essential`, `cmake`, `libssl-dev`, `python3`, затем `cmake`‑сборка с **`-DVSECURE_BUILD_TESTS=ON`**, **`ctest`** (Catch2) и [`scripts/qa_full.sh`](scripts/qa_full.sh).

## Тесты

| Скрипт | Назначение |
|--------|------------|
| [`scripts/run_all_tests.sh`](scripts/run_all_tests.sh) | `ctest` (юнит-тесты Catch2, если собраны через CMake), round-trip, отклонение мусорного кадра |
| [`scripts/qa_full.sh`](scripts/qa_full.sh) | Полный регресс: `run_all_tests`, ~4 MiB, replay, неверный ключ подписи, отсутствующий файл, разрыв TCP при приёме тела, `--host localhost`, каталог вывода только для чтения (**ACK 7** / ошибка записи, а не расшифрование) |
| [`scripts/coverage.sh`](scripts/coverage.sh) | Отдельная сборка в `build_cov/` с `-DVSECURE_ENABLE_COVERAGE=ON`, `ctest`, при наличии — `lcov` |

**Юнит-тесты** (Catch2 v3, подтягиваются через CMake `FetchContent`): метаданные, разбор пакета, `signing_blob`, окно времени / replay-store, `IntegrityChecker` + SHA-256.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVSECURE_BUILD_TESTS=ON
cmake --build build -j
cd build && ctest --output-on-failure
./scripts/qa_full.sh
```

Покрытие строк (gcc/clang, `gcov` / опционально `lcov`):

```bash
./scripts/coverage.sh
```

Требуются `bash`, `cmake` (для юнит-тестов и CI), `make` (альтернативная сборка), `python3`, `openssl`, утилиты `dd`/`head`, `cmp`.

## Коды ACK (ответ получателя)

Константы в `protocol.hpp`: успех `0`, некорректный формат `1`, неверная подпись `2`, повтор `message_id` `3`, сдвиг времени `4`, несовпадение хэша `5`, ошибка расшифрования `6`, ошибка I/O `7`, ошибка соединения `8`.

## Ограничения и безопасность

- Один клиент на запуск получателя; нет интерактивного обмена ключами — только заранее выданные PEM.
- Нет защиты от **утечки метаданных** по размеру/имени файла; нет forward secrecy между сеансами.
- Для production понадобились бы TLS поверх TCP, политика ключей, лимиты размера пакета, таймауты сокетов и аудит.

## Репозиторий

Исходный код: [github.com/paulhowever/VSecureTransfer](https://github.com/paulhowever/VSecureTransfer)

---

*Криптография реализована через EVP API OpenSSL 3; не используйте устаревшие низкоуровневые вызовы в своих форках без необходимости.*
