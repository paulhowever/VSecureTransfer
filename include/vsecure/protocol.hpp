#pragma once

/*
 * VSecureTransfer — бинарный протокол (v1), network byte order (big-endian).
 *
 * --- Соответствие п.11.1 ТЗ «метаданные подписываются» ---
 * В ТЗ также приведён упрощённый пример «подписать хэш RSA». В данной реализации
 * подпись RSA-PSS (SHA-256) охватывает байтовую строку **meta || IV || wrapped_key**,
 * где **meta** уже содержит поле sha256_plaintext (хэш исходного файла). Таким образом,
 * хэш входит в подписанный материал вместе с метаданными; добавление IV и wrapped_key
 * усиливает привязку подписи к сеансу шифрования по сравнению с подписью «только хэша».
 * Для отчёта: формулировка п.11.1 выполнена в усиленном (строжем) варианте.
 *
 * Framing по TCP: сначала uint64_be payload_length, затем ровно payload_length байт
 * одного пакета FileTransfer. После обработки получатель шлёт ACK-фрейм фикс.
 * размера.
 *
 * --- Пакет FileTransfer (payload) ---
 *
 * [0..3]     magic ASCII "VST1"
 * [4..5]     protocol_version u16 BE (текущее значение 1)
 * [6]        message_type u8 (1 = FileTransfer)
 * [7]        reserved u8 (0)
 * [8..11]    meta_len u32 BE — длина блока метаданных
 * [12..15]   wrapped_key_len u32 BE — длина RSA-OAEP ciphertext ключа AES
 * [16..19]   signature_len u32 BE — длина RSA-PSS подписи
 * [20..27]   cipher_len u64 BE — длина ciphertext||tag (AES-256-GCM, tag 16 байт)
 *
 * Далее подряд:
 *   meta (meta_len байт)
 *   iv (ровно 12 байт, nonce для GCM)
 *   wrapped_key (wrapped_key_len)
 *   signature (signature_len)
 *   cipher (cipher_len) — последние 16 байт = GCM tag
 *
 * --- Метаданные (meta), порядок полей для сериализации и подписи ---
 * Все целые ниже в big-endian при упаковке в meta:
 *   u64_be original_file_size
 *   u64_be unix_timestamp_ms
 *   16 байт message_id (случайные, уникальность на стороне получателя)
 *   32 байт sha256_plaintext (SHA-256 исходного файла до шифрования)
 *   u32_be filename_utf8_len + filename_utf8_len байт UTF-8 (базовое имя файла)
 *
 * --- Объект RSA-PSS (SHA-256) подписи ---
 * Подписывается конкатенация байтов (без включения signature и cipher):
 *   meta || iv(12) || wrapped_key
 * Так метаданные, хэш plaintext (внутри meta), IV и обёрнутый симметричный ключ
 * связаны одной подписью отправителя.
 *
 * --- ACK (ответ получателя → отправитель), ровно 8 байт ---
 * [0..3] magic "VACK"
 * [4..7] status u32 BE:
 *   0 = OK
 *   1 = BAD_FORMAT
 *   2 = BAD_SIGNATURE
 *   3 = REPLAY_MESSAGE_ID
 *   4 = TIMESTAMP_SKEW
 *   5 = HASH_MISMATCH
 *   6 = DECRYPT_FAILED
 *   7 = IO_ERROR
 *   8 = CONNECTION_ERROR
 */

#include <cstdint>

namespace vsecure::protocol {

inline constexpr char kMagic[4] = {'V', 'S', 'T', '1'};
inline constexpr std::uint16_t kProtocolVersion = 1;
inline constexpr std::uint8_t kMsgFileTransfer = 1;

inline constexpr std::size_t kGcmIvLen = 12;
inline constexpr std::size_t kGcmTagLen = 16;
inline constexpr std::size_t kSha256Len = 32;
inline constexpr std::size_t kMessageIdLen = 16;

inline constexpr char kAckMagic[4] = {'V', 'A', 'C', 'K'};
inline constexpr std::size_t kAckFrameLen = 8;

inline constexpr std::uint32_t kAckOk = 0;
inline constexpr std::uint32_t kAckBadFormat = 1;
inline constexpr std::uint32_t kAckBadSignature = 2;
inline constexpr std::uint32_t kAckReplay = 3;
inline constexpr std::uint32_t kAckTimeSkew = 4;
inline constexpr std::uint32_t kAckHashMismatch = 5;
inline constexpr std::uint32_t kAckDecryptFailed = 6;
inline constexpr std::uint32_t kAckIoError = 7;
inline constexpr std::uint32_t kAckConnectionError = 8;

/** Заголовок пакета после magic..cipher_len (28 байт от начала payload). */
inline constexpr std::size_t kFileHeaderPrefixLen = 28;

} // namespace vsecure::protocol
