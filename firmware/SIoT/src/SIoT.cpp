/*
 * The SIoT device library (design Section 7, roadmap Phase 5).
 *
 * The order of operations in `send()` is the protocol, and it is worth reading
 * once as a whole before changing any part of it:
 *
 *   seq        = (boot_epoch << 32) | msg_counter++      boot_epoch is already in flash
 *   nonce      = 0x00000000 || seq
 *   AAD        = 0x01 || DEVICE_ID || 0x00 || seq
 *   plaintext  = CBOR { t, r }
 *   ciphertext = AES-256-GCM(device_data_key, nonce, plaintext, AAD) || tag
 *   sig        = Ed25519(sign_key, AAD || nonce || ciphertext)
 *
 * Nothing in it needs a random number generator, and that is deliberate: a
 * device that has just been power-cycled has no entropy worth trusting, and the
 * nonce is a function of a counter that was persisted before it was used.
 */

#include "SIoT.h"

#include <HTTPClient.h>
#include <Preferences.h>
#include <WiFiClientSecure.h>
#include <cbor.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <sodium.h>
#include <string.h>
#include <time.h>

/* --- storage -------------------------------------------------------------- */

/*
 * The dedicated partition from `firmware/esp32-provisioning/partitions.csv`,
 * never the stock `nvs` the application owns. A sketch's own
 * `Preferences.clear()` or an `nvs_flash_erase()` wipes that one, and a
 * factory-reset routine is an ordinary thing for a sketch to have.
 */
static const char *NVS_PARTITION = "siot";
static const char *NVS_NAMESPACE = "siot";
static const char *KEY_ID = "id";
static const char *KEY_SECRET = "secret";

/*
 * `boot_epoch` lives beside the credentials rather than in the application's
 * own NVS, and that placement is load-bearing. Losing it is not an
 * inconvenience: the device restarts at epoch 1, repeats a `seq`, and reuses a
 * nonce, which in GCM leaks the XOR of two plaintexts and the authentication
 * subkey. Putting it where an application factory-reset can reach it would make
 * that a routine occurrence rather than an unlikely one.
 *
 * `SIOT ERASE` in the provisioning sketch deliberately leaves this key alone: a
 * counter is not a secret, and a board erased and later re-provisioned for the
 * same device keeps a sequence that only ever moves forward.
 */
static const char *KEY_BOOT_EPOCH = "boot";

/*
 * The highest `command_seq` this device has executed (roadmap 11.3). It lives in
 * the `siot` partition beside `boot_epoch` for the same reason: a factory reset
 * that reached it would let an old, still-valid command ciphertext run again,
 * and a replayed command is a physical action repeating.
 */
static const char *KEY_COMMAND_SEQ = "cmdseq";

/* --- key derivation ------------------------------------------------------- */

/*
 * The two labels from design 5.1, byte for byte. These are a wire format shared
 * with every port and with the browser that registered this device's public
 * key: an "equivalent" label produces a device whose records nothing can open
 * and whose signatures nothing accepts, with no negotiation step to catch it.
 */
static const char *HKDF_INFO_DATA = "siot/device/data/v1";
static const char *HKDF_INFO_SIGN = "siot/device/sign/v1";
static const char *HKDF_INFO_NOTIFY = "siot/device/notify/v1";   /* roadmap 10.1 */
static const char *HKDF_INFO_COMMAND = "siot/device/command/v1"; /* roadmap 11.1 */

/** Fixed v1 protocol constants, not wire fields. See docs/protocol.md section 5. */
static const uint8_t PROTOCOL_VERSION = 1;
static const uint8_t RECORD_TYPE_V1 = 0;

/** Nothing here is worth waiting on longer than this; a sensor has a loop to get back to. */
static const uint16_t HTTP_TIMEOUT_MS = 12000;
static const uint16_t RETRY_BASE_DELAY_MS = 400;

/** A clock this far behind is one that was never set, not one that is wrong. */
static const time_t PLAUSIBLE_EPOCH = 1600000000;

/* --- base64url ------------------------------------------------------------ */

/*
 * Hand-rolled for the same reason the provisioning sketch's is: the core's
 * libb64 does padded standard base64, which is the wrong alphabet and the wrong
 * padding for every value in this protocol. Encode only. Nothing here ever
 * decodes, because nothing is ever sent to this device.
 */
static const char B64URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** `out` must hold 4*ceil(len/3) + 1 bytes. Returns the text length. */
static size_t b64urlEncode(const uint8_t *in, size_t len, char *out) {
  size_t o = 0;
  for (size_t i = 0; i < len; i += 3) {
    uint32_t block = (uint32_t)in[i] << 16;
    size_t have = 1;
    if (i + 1 < len) {
      block |= (uint32_t)in[i + 1] << 8;
      have = 2;
    }
    if (i + 2 < len) {
      block |= (uint32_t)in[i + 2];
      have = 3;
    }
    out[o++] = B64URL[(block >> 18) & 63];
    out[o++] = B64URL[(block >> 12) & 63];
    if (have >= 2) out[o++] = B64URL[(block >> 6) & 63];
    if (have >= 3) out[o++] = B64URL[block & 63];
  }
  out[o] = '\0';
  return o;
}

/** Returns the decoded length, or -1 on a character outside the alphabet or an impossible length. */
static int b64urlDecode(const char *in, size_t inLen, uint8_t *out, size_t capacity) {
  if (inLen % 4 == 1) return -1;
  size_t o = 0;
  uint32_t block = 0;
  int bits = 0;
  for (size_t i = 0; i < inLen; i += 1) {
    const char *at = strchr(B64URL, in[i]);
    if (in[i] == '\0' || at == nullptr) return -1;
    block = (block << 6) | (uint32_t)(at - B64URL);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= capacity) return -1;
      out[o++] = (uint8_t)((block >> bits) & 0xff);
    }
  }
  return (int)o;
}

/* --- status --------------------------------------------------------------- */

const char *SIoTStatusName(SIoTStatus status) {
  switch (status) {
    case SIoTStatus::Ok: return "Ok";
    case SIoTStatus::NotBegun: return "NotBegun";
    case SIoTStatus::NotProvisioned: return "NotProvisioned";
    case SIoTStatus::StorageFailure: return "StorageFailure";
    case SIoTStatus::CryptoFailure: return "CryptoFailure";
    case SIoTStatus::NoReadings: return "NoReadings";
    case SIoTStatus::PayloadTooLarge: return "PayloadTooLarge";
    case SIoTStatus::NetworkFailure: return "NetworkFailure";
    case SIoTStatus::Rejected: return "Rejected";
    case SIoTStatus::DeviceUnknown: return "DeviceUnknown";
    case SIoTStatus::SequenceRefused: return "SequenceRefused";
    case SIoTStatus::ServerFailure: return "ServerFailure";
  }
  return "Unknown";
}

/* --- lifecycle ------------------------------------------------------------ */

SIoTClient::SIoTClient()
    : baseUrl_(nullptr),
      caCertPem_(nullptr),
      ready_(false),
      deleted_(false),
      error_(""),
      bootEpoch_(0),
      msgCounter_(0),
      readingCount_(0) {
  memset(deviceId_, 0, sizeof(deviceId_));
  memset(deviceIdText_, 0, sizeof(deviceIdText_));
  memset(dataKey_, 0, sizeof(dataKey_));
  memset(notifyKey_, 0, sizeof(notifyKey_));
  memset(commandKey_, 0, sizeof(commandKey_));
  memset(signSecret_, 0, sizeof(signSecret_));
}

void SIoTClient::setServer(const char *baseUrl, const char *caCertPem) {
  baseUrl_ = baseUrl;
  caCertPem_ = caCertPem;
}

void SIoTClient::fail(const char *message) { error_ = message; }

/*
 * A transport failure with the reason attached. HTTPClient's negative code says
 * *that* it failed (refused, timed out, send/read error) and mbedTLS says *why*
 * a handshake failed (an untrusted or expired certificate shows up here and
 * nowhere else). Keeping both is what lets a person tell a firewall from a
 * pin mismatch from a board whose clock is wrong, which "could not reach the
 * server" cannot.
 */
void SIoTClient::failNetwork(const char *message, int httpCode, int tlsCode, const char *tlsReason) {
  if (tlsCode != 0) {
    snprintf(detail_, sizeof(detail_), "%s (%s; tls %d: %s)", message,
             HTTPClient::errorToString(httpCode).c_str(), tlsCode, tlsReason);
  } else {
    snprintf(detail_, sizeof(detail_), "%s (%s)", message, HTTPClient::errorToString(httpCode).c_str());
  }
  error_ = detail_;
}

bool SIoTClient::loadCredentials(uint8_t *secret) {
  Preferences store;
  /* Read-write even to read: a read-only open of a namespace that has never
     been written fails, and an unprovisioned board is an ordinary state to
     discover rather than an error to crash on. */
  if (!store.begin(NVS_NAMESPACE, false, NVS_PARTITION)) {
    fail("the siot NVS partition could not be opened: is this board flashed with the provisioning partition table?");
    return false;
  }

  const bool present = store.getBytesLength(KEY_ID) == SIOT_DEVICE_ID_BYTES &&
                       store.getBytesLength(KEY_SECRET) == SIOT_DEVICE_SECRET_BYTES;
  if (!present) {
    store.end();
    fail("this board has no credentials: provision it from the SIoT web client first");
    return false;
  }

  const bool read = store.getBytes(KEY_ID, deviceId_, SIOT_DEVICE_ID_BYTES) == SIOT_DEVICE_ID_BYTES &&
                    store.getBytes(KEY_SECRET, secret, SIOT_DEVICE_SECRET_BYTES) == SIOT_DEVICE_SECRET_BYTES;
  store.end();

  if (!read) {
    fail("the credentials in NVS could not be read");
    return false;
  }
  b64urlEncode(deviceId_, SIOT_DEVICE_ID_BYTES, deviceIdText_);
  return true;
}

bool SIoTClient::advanceBootEpoch() {
  Preferences store;
  if (!store.begin(NVS_NAMESPACE, false, NVS_PARTITION)) {
    fail("the siot NVS partition could not be opened to advance boot_epoch");
    return false;
  }

  const uint32_t previous = store.getUInt(KEY_BOOT_EPOCH, 0);
  if (previous == UINT32_MAX) {
    /* 4.3 billion boots. Continuing would wrap to 0 and start repeating seq
       values that have already been used, which is exactly the nonce reuse this
       counter exists to prevent, so it stops instead. */
    store.end();
    fail("boot_epoch has reached its maximum; this device needs a new DEVICE_SECRET");
    return false;
  }

  const uint32_t next = previous + 1;
  const bool wrote = store.putUInt(KEY_BOOT_EPOCH, next) == sizeof(uint32_t);

  /* Read it back before trusting it. An API that returned success is not
     evidence that flash changed, and this is the one value whose loss breaks
     the cryptography rather than merely losing a reading. */
  const bool verified = wrote && store.getUInt(KEY_BOOT_EPOCH, 0) == next;
  store.end();

  if (!verified) {
    fail("boot_epoch could not be committed to flash; refusing to produce records without it");
    return false;
  }

  bootEpoch_ = next;
  msgCounter_ = 0;
  return true;
}

bool SIoTClient::begin() {
  ready_ = false;
  deleted_ = false;
  error_ = "";
  readingCount_ = 0;

  if (baseUrl_ == nullptr || caCertPem_ == nullptr) {
    fail("setServer() must be called before begin()");
    return false;
  }

  /* Ed25519 signing is deterministic and needs no entropy, but libsodium wants
     its own initialisation before any call into it. 1 means "already done". */
  if (sodium_init() < 0) {
    fail("libsodium failed to initialise");
    return false;
  }

  uint8_t secret[SIOT_DEVICE_SECRET_BYTES];
  if (!loadCredentials(secret)) {
    sodium_memzero(secret, sizeof(secret));
    return false;
  }

  const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  uint8_t signSeed[SIOT_KEY_BYTES];

  /* Empty HKDF salt, per docs/protocol.md section 2: the IKM is already 32 bytes
     of CSPRNG output, and RFC 5869 section 3.1 covers exactly this case. */
  const bool derived =
      sha256 != nullptr &&
      mbedtls_hkdf(sha256, nullptr, 0, secret, sizeof(secret),
                   (const unsigned char *)HKDF_INFO_DATA, strlen(HKDF_INFO_DATA),
                   dataKey_, sizeof(dataKey_)) == 0 &&
      mbedtls_hkdf(sha256, nullptr, 0, secret, sizeof(secret),
                   (const unsigned char *)HKDF_INFO_NOTIFY, strlen(HKDF_INFO_NOTIFY),
                   notifyKey_, sizeof(notifyKey_)) == 0 &&
      mbedtls_hkdf(sha256, nullptr, 0, secret, sizeof(secret),
                   (const unsigned char *)HKDF_INFO_COMMAND, strlen(HKDF_INFO_COMMAND),
                   commandKey_, sizeof(commandKey_)) == 0 &&
      mbedtls_hkdf(sha256, nullptr, 0, secret, sizeof(secret),
                   (const unsigned char *)HKDF_INFO_SIGN, strlen(HKDF_INFO_SIGN),
                   signSeed, sizeof(signSeed)) == 0;

  /* The secret has done its whole job by here. Both keys are reproducible from
     it and it is never needed again, so it does not stay in RAM for the life of
     the sketch waiting to turn up in a core dump. */
  sodium_memzero(secret, sizeof(secret));

  if (!derived) {
    sodium_memzero(signSeed, sizeof(signSeed));
    fail("key derivation failed");
    return false;
  }

  uint8_t signPub[crypto_sign_ed25519_PUBLICKEYBYTES];
  const bool keyed = crypto_sign_ed25519_seed_keypair(signPub, signSecret_, signSeed) == 0;
  sodium_memzero(signSeed, sizeof(signSeed));

  if (!keyed) {
    fail("the signing keypair could not be derived");
    return false;
  }

  if (!advanceBootEpoch()) return false;

  ready_ = true;
  return true;
}

/* --- readings ------------------------------------------------------------- */

bool SIoTClient::addNamed(const char *name, Reading **slot) {
  if (readingCount_ >= SIOT_MAX_READINGS) {
    fail("too many readings in one record");
    return false;
  }
  if (name == nullptr || name[0] == '\0' || strlen(name) > SIOT_READING_NAME_MAX) {
    fail("a reading name must be 1 to 24 characters");
    return false;
  }

  Reading *reading = &readings_[readingCount_];
  strncpy(reading->name, name, SIOT_READING_NAME_MAX);
  reading->name[SIOT_READING_NAME_MAX] = '\0';
  reading->text[0] = '\0';
  *slot = reading;
  readingCount_ += 1;
  return true;
}

bool SIoTClient::addReading(const char *name, double value) {
  Reading *reading;
  if (!addNamed(name, &reading)) return false;
  reading->kind = Reading::Kind::Double;
  reading->number = value;
  return true;
}

bool SIoTClient::addReading(const char *name, int value) {
  return addReading(name, (long long)value);
}

bool SIoTClient::addReading(const char *name, long long value) {
  Reading *reading;
  if (!addNamed(name, &reading)) return false;
  reading->kind = Reading::Kind::Int;
  reading->integer = value;
  return true;
}

bool SIoTClient::addReading(const char *name, bool value) {
  Reading *reading;
  if (!addNamed(name, &reading)) return false;
  reading->kind = Reading::Kind::Bool;
  reading->flag = value;
  return true;
}

bool SIoTClient::addReading(const char *name, const char *value) {
  if (value == nullptr || strlen(value) > SIOT_READING_TEXT_MAX) {
    fail("a text reading must be 32 characters or fewer");
    return false;
  }
  Reading *reading;
  if (!addNamed(name, &reading)) return false;
  reading->kind = Reading::Kind::Text;
  strncpy(reading->text, value, SIOT_READING_TEXT_MAX);
  reading->text[SIOT_READING_TEXT_MAX] = '\0';
  return true;
}

void SIoTClient::clearReadings() { readingCount_ = 0; }

/* --- the record ----------------------------------------------------------- */

/**
 * `CBOR { "t": <uint>, "r": { ... } }`, per docs/protocol.md section 6.
 *
 * Key ordering is not deterministic here and does not need to be: nothing
 * verifies the encoding, because the signature covers whatever bytes this
 * actually produces. The published test vectors assume the browser encoder's
 * ordering, which is why a firmware record and a vector record differ in bytes
 * while both being perfectly valid.
 *
 * @return the encoded length, or 0 if it did not fit.
 */
size_t SIoTClient::encodePayload(uint8_t *out, size_t capacity, uint32_t timestamp) {
  CborEncoder root;
  CborEncoder envelope;
  CborEncoder readings;

  cbor_encoder_init(&root, out, capacity, 0);
  if (cbor_encoder_create_map(&root, &envelope, 2) != CborNoError) return 0;

  if (cbor_encode_text_stringz(&envelope, "t") != CborNoError) return 0;
  if (cbor_encode_uint(&envelope, timestamp) != CborNoError) return 0;

  if (cbor_encode_text_stringz(&envelope, "r") != CborNoError) return 0;
  if (cbor_encoder_create_map(&envelope, &readings, readingCount_) != CborNoError) return 0;

  for (size_t i = 0; i < readingCount_; i += 1) {
    const Reading &reading = readings_[i];
    if (cbor_encode_text_stringz(&readings, reading.name) != CborNoError) return 0;

    CborError encoded = CborNoError;
    switch (reading.kind) {
      case Reading::Kind::Double:
        encoded = cbor_encode_double(&readings, reading.number);
        break;
      case Reading::Kind::Int:
        encoded = cbor_encode_int(&readings, reading.integer);
        break;
      case Reading::Kind::Bool:
        encoded = cbor_encode_boolean(&readings, reading.flag);
        break;
      case Reading::Kind::Text:
        encoded = cbor_encode_text_stringz(&readings, reading.text);
        break;
    }
    if (encoded != CborNoError) return 0;
  }

  if (cbor_encoder_close_container(&envelope, &readings) != CborNoError) return 0;
  if (cbor_encoder_close_container(&root, &envelope) != CborNoError) return 0;

  return cbor_encoder_get_buffer_size(&root, out);
}

void SIoTClient::buildNonce(uint8_t *nonce, uint64_t seq) const {
  memset(nonce, 0, 4);
  for (int i = 0; i < 8; i += 1) {
    nonce[4 + i] = (uint8_t)((seq >> (56 - 8 * i)) & 0xff);
  }
}

void SIoTClient::buildAad(uint8_t *aad, uint64_t seq) const {
  aad[0] = PROTOCOL_VERSION;
  memcpy(aad + 1, deviceId_, SIOT_DEVICE_ID_BYTES);
  aad[1 + SIOT_DEVICE_ID_BYTES] = RECORD_TYPE_V1;
  for (int i = 0; i < 8; i += 1) {
    aad[2 + SIOT_DEVICE_ID_BYTES + i] = (uint8_t)((seq >> (56 - 8 * i)) & 0xff);
  }
}

SIoTStatus SIoTClient::buildRecord(char *out, size_t capacity, size_t *written) {
  if (written != nullptr) *written = 0;
  if (!ready_) {
    fail("begin() has not run, or it failed");
    return SIoTStatus::NotBegun;
  }
  if (deleted_) {
    /* Latched by a previous 404. Failing here costs no radio time, which is the
       whole point: a deleted device that keeps retrying is a board flattening
       its battery against a server that will never accept it. */
    fail("this device has been deleted on the server; reprovision the board");
    return SIoTStatus::DeviceUnknown;
  }
  if (readingCount_ == 0) {
    fail("no readings were added");
    return SIoTStatus::NoReadings;
  }

  /* The counter advances once per *record*, not once per upload attempt. A
     retry below re-sends the same bytes at the same seq, which is the same
     record; building a second record at the same seq would be nonce reuse. */
  const uint64_t seq = ((uint64_t)bootEpoch_ << 32) | (uint64_t)msgCounter_;
  msgCounter_ += 1;

  const time_t now = time(nullptr);
  const uint32_t timestamp = now >= PLAUSIBLE_EPOCH ? (uint32_t)now : 0;

  uint8_t payload[SIOT_PAYLOAD_MAX];
  const size_t payloadLen = encodePayload(payload, sizeof(payload), timestamp);
  clearReadings();
  if (payloadLen == 0) {
    fail("the readings did not fit in one record");
    return SIoTStatus::PayloadTooLarge;
  }

  return sealAndSerialise(payload, payloadLen, dataKey_, seq, out, capacity, written);
}

/**
 * Builds a notification record (roadmap 10.2). Same `seq` sequence as readings,
 * same signature, same AAD; the payload says it is a notification and the key is
 * `device_notify_key`. Pending readings are left alone.
 */
SIoTStatus SIoTClient::buildNotification(SIoTSeverity severity, const char *message, char *out,
                                         size_t capacity, size_t *written) {
  if (written != nullptr) *written = 0;
  if (!ready_) {
    fail("begin() has not run, or it failed");
    return SIoTStatus::NotBegun;
  }
  if (deleted_) {
    fail("this device has been deleted on the server; reprovision the board");
    return SIoTStatus::DeviceUnknown;
  }
  if (message == nullptr || message[0] == '\0') {
    fail("a notification needs a message");
    return SIoTStatus::NoReadings;
  }
  /* Bounded here, not just in the dashboard: an unbounded ciphertext length
     would let the payload size leak what the device is saying. */
  if (strlen(message) > SIOT_NOTIFY_MESSAGE_MAX) {
    fail("the notification message is too long");
    return SIoTStatus::PayloadTooLarge;
  }

  const uint64_t seq = ((uint64_t)bootEpoch_ << 32) | (uint64_t)msgCounter_;
  msgCounter_ += 1;

  const time_t now = time(nullptr);
  const uint32_t timestamp = now >= PLAUSIBLE_EPOCH ? (uint32_t)now : 0;

  static const char *const SEVERITY_NAMES[] = {"info", "warning", "alert", "critical"};
  const uint8_t level = (uint8_t)severity;
  if (level >= sizeof(SEVERITY_NAMES) / sizeof(SEVERITY_NAMES[0])) {
    fail("unknown notification severity");
    return SIoTStatus::PayloadTooLarge;
  }

  uint8_t payload[SIOT_PAYLOAD_MAX];
  CborEncoder root;
  CborEncoder map;
  cbor_encoder_init(&root, payload, sizeof(payload), 0);
  const bool encoded =
      cbor_encoder_create_map(&root, &map, 4) == CborNoError &&
      cbor_encode_text_stringz(&map, "t") == CborNoError &&
      cbor_encode_uint(&map, timestamp) == CborNoError &&
      cbor_encode_text_stringz(&map, "type") == CborNoError &&
      cbor_encode_text_stringz(&map, "notification") == CborNoError &&
      cbor_encode_text_stringz(&map, "severity") == CborNoError &&
      cbor_encode_text_stringz(&map, SEVERITY_NAMES[level]) == CborNoError &&
      cbor_encode_text_stringz(&map, "message") == CborNoError &&
      cbor_encode_text_stringz(&map, message) == CborNoError &&
      cbor_encoder_close_container(&root, &map) == CborNoError;
  if (!encoded) {
    fail("the notification did not fit in one record");
    return SIoTStatus::PayloadTooLarge;
  }
  const size_t payloadLen = cbor_encoder_get_buffer_size(&root, payload);
  return sealAndSerialise(payload, payloadLen, notifyKey_, seq, out, capacity, written);
}

/** Build a notification, then get it there. Retries re-send the same bytes, as `send()` does. */
SIoTStatus SIoTClient::notify(SIoTSeverity severity, const char *message, uint8_t attempts) {
  char body[SIOT_RECORD_BODY_MAX];
  const SIoTStatus built = buildNotification(severity, message, body, sizeof(body));
  if (built != SIoTStatus::Ok) return built;

  SIoTStatus status = SIoTStatus::NetworkFailure;
  for (uint8_t attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) delay(RETRY_BASE_DELAY_MS << (attempt - 1));
    status = post(body);
    if (status != SIoTStatus::NetworkFailure && status != SIoTStatus::ServerFailure) break;
  }
  return status;
}

/**
 * Everything after the payload is encoded: encrypt under `key`, sign, serialise.
 *
 * Shared by readings and notifications on purpose. They differ only in the
 * payload and the key; the `seq`, the nonce, the AAD (with its constant record
 * type byte) and the signature are the same code path, so there is no second
 * place for a check to be subtly weaker (ROADMAP 10.0). The caller allocates
 * `seq` from the one `msgCounter_`, which is what keeps two key streams from
 * ever sharing a nonce.
 */
SIoTStatus SIoTClient::sealAndSerialise(uint8_t *payload, size_t payloadLen, const uint8_t *key,
                                        uint64_t seq, char *out, size_t capacity, size_t *written) {
  uint8_t nonce[SIOT_NONCE_BYTES];
  uint8_t aad[SIOT_AAD_BYTES];
  buildNonce(nonce, seq);
  buildAad(aad, seq);

  /* ciphertext || tag, which is what the wire format means by "ciphertext". */
  uint8_t sealed[SIOT_PAYLOAD_MAX + SIOT_TAG_BYTES];
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  const bool encrypted =
      mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 8 * SIOT_KEY_BYTES) == 0 &&
      mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, payloadLen, nonce, SIOT_NONCE_BYTES,
                                aad, SIOT_AAD_BYTES, payload, sealed, SIOT_TAG_BYTES,
                                sealed + payloadLen) == 0;
  mbedtls_gcm_free(&gcm);
  sodium_memzero(payload, payloadLen);

  if (!encrypted) {
    fail("AES-256-GCM encryption failed");
    return SIoTStatus::CryptoFailure;
  }
  const size_t sealedLen = payloadLen + SIOT_TAG_BYTES;

  /* AAD || nonce || ciphertext, in that order and with no separators. The
     signature therefore covers the device identity, the record type and the
     sequence position, not merely the payload. */
  uint8_t message[SIOT_AAD_BYTES + SIOT_NONCE_BYTES + sizeof(sealed)];
  memcpy(message, aad, SIOT_AAD_BYTES);
  memcpy(message + SIOT_AAD_BYTES, nonce, SIOT_NONCE_BYTES);
  memcpy(message + SIOT_AAD_BYTES + SIOT_NONCE_BYTES, sealed, sealedLen);
  const size_t messageLen = SIOT_AAD_BYTES + SIOT_NONCE_BYTES + sealedLen;

  uint8_t signature[SIOT_SIG_BYTES];
  if (crypto_sign_ed25519_detached(signature, nullptr, message, messageLen, signSecret_) != 0) {
    fail("signing failed");
    return SIoTStatus::CryptoFailure;
  }

  char nonceText[17];
  char sealedText[4 * ((sizeof(sealed) + 2) / 3) + 1];
  char sigText[89];
  b64urlEncode(nonce, SIOT_NONCE_BYTES, nonceText);
  b64urlEncode(sealed, sealedLen, sealedText);
  b64urlEncode(signature, SIOT_SIG_BYTES, sigText);

  /* `seq` goes on the wire as a decimal string, never as a JSON number: it is a
     uint64 and JSON numbers are doubles, so a parser on either side would read
     a different value back out for anything past 2^53. */
  char seqText[21];
  snprintf(seqText, sizeof(seqText), "%llu", (unsigned long long)seq);

  const int length = snprintf(out, capacity,
                              "{\"device_id\":\"%s\",\"seq\":\"%s\",\"nonce\":\"%s\","
                              "\"ciphertext\":\"%s\",\"sig\":\"%s\"}",
                              deviceIdText_, seqText, nonceText, sealedText, sigText);
  if (length <= 0 || (size_t)length >= capacity) {
    fail("the request body did not fit the buffer it was given");
    return SIoTStatus::PayloadTooLarge;
  }

  if (written != nullptr) *written = (size_t)length;
  error_ = "";
  return SIoTStatus::Ok;
}
/**
 * Build one record, then get it there.
 *
 * The retries re-send the *same bytes* rather than rebuilding, which is the
 * distinction the whole sequencing scheme rests on: an identical record at an
 * identical `seq` is the same record, while a fresh plaintext at that `seq`
 * would reuse the nonce. That is why the body is built once, outside the loop.
 */
SIoTStatus SIoTClient::send(uint8_t attempts) {
  char body[SIOT_RECORD_BODY_MAX];
  const SIoTStatus built = buildRecord(body, sizeof(body));
  if (built != SIoTStatus::Ok) return built;

  SIoTStatus status = SIoTStatus::NetworkFailure;
  for (uint8_t attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) delay(RETRY_BASE_DELAY_MS << (attempt - 1));
    status = post(body);

    /* Only the transient classes are worth another go. A 400 or a 401 is a
       record the server will refuse identically forever, and a 404 means the
       device is gone; retrying either is noise on the wire and current out of
       the battery. */
    if (status != SIoTStatus::NetworkFailure && status != SIoTStatus::ServerFailure) break;
  }
  return status;
}


/* --- commands (roadmap 11.3, 11.4) --------------------------------------- */

static const uint8_t COMMAND_PROTOCOL_VERSION = 1;
static const uint8_t COMMAND_CLASS_V1 = 1;
static const size_t COMMAND_RESPONSE_MAX = 8192;

/** Copies the string value of `"key":"..."` found between `from` and `to`. */
static bool jsonString(const char *from, const char *to, const char *key, char *out, size_t capacity) {
  char needle[24];
  snprintf(needle, sizeof(needle), "\"%s\":\"", key);
  const char *at = strstr(from, needle);
  if (at == nullptr || at >= to) return false;
  at += strlen(needle);
  const char *end = strchr(at, '"');
  if (end == nullptr || end > to || (size_t)(end - at) >= capacity) return false;
  memcpy(out, at, (size_t)(end - at));
  out[end - at] = '\0';
  return true;
}

bool SIoTCommand::getInt(const char *name, long long *out) const {
  CborParser parser;
  CborValue it, found;
  int64_t value = 0;
  if (cbor_parser_init(args_, argsLen_, 0, &parser, &it) != CborNoError) return false;
  if (!cbor_value_is_map(&it) || cbor_value_map_find_value(&it, name, &found) != CborNoError) return false;
  if (!cbor_value_is_integer(&found) || cbor_value_get_int64(&found, &value) != CborNoError) return false;
  *out = value;
  return true;
}

bool SIoTCommand::getBool(const char *name, bool *out) const {
  CborParser parser;
  CborValue it, found;
  if (cbor_parser_init(args_, argsLen_, 0, &parser, &it) != CborNoError) return false;
  if (!cbor_value_is_map(&it) || cbor_value_map_find_value(&it, name, &found) != CborNoError) return false;
  return cbor_value_is_boolean(&found) && cbor_value_get_boolean(&found, out) == CborNoError;
}

bool SIoTCommand::getDouble(const char *name, double *out) const {
  CborParser parser;
  CborValue it, found;
  if (cbor_parser_init(args_, argsLen_, 0, &parser, &it) != CborNoError) return false;
  if (!cbor_value_is_map(&it) || cbor_value_map_find_value(&it, name, &found) != CborNoError) return false;
  if (cbor_value_is_double(&found)) return cbor_value_get_double(&found, out) == CborNoError;
  if (cbor_value_is_float(&found)) {
    float f = 0;
    if (cbor_value_get_float(&found, &f) != CborNoError) return false;
    *out = f;
    return true;
  }
  long long integer = 0;
  if (!getInt(name, &integer)) return false;
  *out = (double)integer;
  return true;
}

bool SIoTCommand::getText(const char *name, char *out, size_t capacity) const {
  CborParser parser;
  CborValue it, found;
  if (cbor_parser_init(args_, argsLen_, 0, &parser, &it) != CborNoError) return false;
  if (!cbor_value_is_map(&it) || cbor_value_map_find_value(&it, name, &found) != CborNoError) return false;
  if (!cbor_value_is_text_string(&found)) return false;
  size_t length = capacity;
  return cbor_value_copy_text_string(&found, out, &length, nullptr) == CborNoError;
}

/**
 * Opens one command ciphertext and parses `{ command_seq, type, args }`.
 * False for anything that does not open: a stranger polling the endpoint cannot
 * produce a valid one, so a failure means corruption and is not worth alarming on.
 */
bool SIoTClient::openCommand(const uint8_t *nonce, const uint8_t *sealed, size_t sealedLen,
                             uint8_t *plain, uint64_t *seq, SIoTCommand *command) {
  if (sealedLen <= SIOT_TAG_BYTES) return false;
  const size_t plainLen = sealedLen - SIOT_TAG_BYTES;

  /* version(1B) || DEVICE_ID(16B) || command-class(1B), matching command.js. */
  uint8_t aad[1 + SIOT_DEVICE_ID_BYTES + 1];
  aad[0] = COMMAND_PROTOCOL_VERSION;
  memcpy(aad + 1, deviceId_, SIOT_DEVICE_ID_BYTES);
  aad[1 + SIOT_DEVICE_ID_BYTES] = COMMAND_CLASS_V1;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  const bool opened =
      mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, commandKey_, 8 * SIOT_KEY_BYTES) == 0 &&
      mbedtls_gcm_auth_decrypt(&gcm, plainLen, nonce, SIOT_NONCE_BYTES, aad, sizeof(aad),
                               sealed + plainLen, SIOT_TAG_BYTES, sealed, plain) == 0;
  mbedtls_gcm_free(&gcm);
  if (!opened) return false;

  CborParser parser;
  CborValue root, field;
  if (cbor_parser_init(plain, plainLen, 0, &parser, &root) != CborNoError || !cbor_value_is_map(&root)) {
    return false;
  }

  uint64_t sequence = 0;
  if (cbor_value_map_find_value(&root, "command_seq", &field) != CborNoError ||
      !cbor_value_is_unsigned_integer(&field) || cbor_value_get_uint64(&field, &sequence) != CborNoError) {
    return false;
  }

  size_t typeLen = sizeof(command->type_);
  if (cbor_value_map_find_value(&root, "type", &field) != CborNoError ||
      !cbor_value_is_text_string(&field) ||
      cbor_value_copy_text_string(&field, command->type_, &typeLen, nullptr) != CborNoError) {
    return false;
  }

  /* The args map is kept as its own encoded bytes: `ptr` before and after
     skipping it brackets exactly that item. */
  if (cbor_value_map_find_value(&root, "args", &field) != CborNoError || !cbor_value_is_map(&field)) {
    return false;
  }
  const uint8_t *argsStart = cbor_value_get_next_byte(&field);
  CborValue after = field;
  if (cbor_value_advance(&after) != CborNoError) return false;
  command->args_ = argsStart;
  command->argsLen_ = (size_t)(cbor_value_get_next_byte(&after) - argsStart);

  command->seq_ = sequence;
  *seq = sequence;
  return true;
}

/** Persists the new mark and reads it back: the same discipline as `boot_epoch`. */
bool SIoTClient::commitCommandSeq(uint64_t seq) {
  Preferences store;
  if (!store.begin(NVS_NAMESPACE, false, NVS_PARTITION)) return false;
  const bool wrote = store.putULong64(KEY_COMMAND_SEQ, seq) == sizeof(uint64_t);
  const bool verified = wrote && store.getULong64(KEY_COMMAND_SEQ, 0) == seq;
  store.end();
  return verified;
}

SIoTStatus SIoTClient::pollCommands(SIoTCommandHandler handler) {
  if (!ready_) {
    fail("begin() has not run, or it failed");
    return SIoTStatus::NotBegun;
  }
  if (deleted_) {
    fail("this device has been deleted on the server; reprovision the board");
    return SIoTStatus::DeviceUnknown;
  }

  uint64_t mark = 0;
  {
    Preferences store;
    if (!store.begin(NVS_NAMESPACE, false, NVS_PARTITION)) {
      fail("the siot NVS partition could not be opened to read the command mark");
      return SIoTStatus::StorageFailure;
    }
    mark = store.getULong64(KEY_COMMAND_SEQ, 0);
    store.end();
  }

  WiFiClientSecure tls;
  tls.setCACert(caCertPem_);
  tls.setTimeout(HTTP_TIMEOUT_MS / 1000);

  char url[200];
  snprintf(url, sizeof(url), "%s/siot/devices/%s/commands", baseUrl_, deviceIdText_);

  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.setConnectTimeout(HTTP_TIMEOUT_MS);
  if (!http.begin(tls, url)) {
    fail("the server URL could not be parsed");
    return SIoTStatus::NetworkFailure;
  }
  const int code = http.GET();
  if (code <= 0) {
    failNetwork("could not reach the server", code, 0, "");
    http.end();
    return SIoTStatus::NetworkFailure;
  }
  if (code == 404) {
    http.end();
    deleted_ = true;
    fail("this device has been deleted on the server; reprovision the board");
    return SIoTStatus::DeviceUnknown;
  }
  if (code != 200) {
    http.end();
    fail("the server did not answer the command poll with 200");
    return code >= 500 ? SIoTStatus::ServerFailure : SIoTStatus::Rejected;
  }
  if (http.getSize() > (int)COMMAND_RESPONSE_MAX) {
    http.end();
    fail("the command queue is larger than this device will read in one poll");
    return SIoTStatus::PayloadTooLarge;
  }
  const String response = http.getString();
  http.end();

  /* The three working buffers are ~3.7 KB together, which is a lot to ask of the
     8 KB loop task stack with TLS state also in play, so they live on the heap. */
  static const size_t SEALED_MAX = 1100;
  static const size_t SEALED_TEXT_MAX = 1500;
  uint8_t *sealed = (uint8_t *)malloc(SEALED_MAX);
  uint8_t *plain = (uint8_t *)malloc(SEALED_MAX);
  char *sealedText = (char *)malloc(SEALED_TEXT_MAX);
  if (sealed == nullptr || plain == nullptr || sealedText == nullptr) {
    free(sealed);
    free(plain);
    free(sealedText);
    fail("out of memory reading the command queue");
    return SIoTStatus::StorageFailure;
  }

  const char *cursorAt = strstr(response.c_str(), "\"cursor\":");
  uint64_t highestCursor = 0;
  bool sawAny = false;

  while (cursorAt != nullptr) {
    const char *next = strstr(cursorAt + 9, "\"cursor\":");
    const char *objectEnd = next != nullptr ? next : response.c_str() + response.length();

    char cursorText[24], nonceText[24];
    uint8_t nonce[SIOT_NONCE_BYTES];
    int nonceLen = -1, sealedLen = -1;
    if (jsonString(cursorAt, objectEnd, "cursor", cursorText, sizeof(cursorText)) &&
        jsonString(cursorAt, objectEnd, "nonce", nonceText, sizeof(nonceText)) &&
        jsonString(cursorAt, objectEnd, "ciphertext", sealedText, SEALED_TEXT_MAX)) {
      const uint64_t cursor = strtoull(cursorText, nullptr, 10);
      nonceLen = b64urlDecode(nonceText, strlen(nonceText), nonce, sizeof(nonce));
      sealedLen = b64urlDecode(sealedText, strlen(sealedText), sealed, SEALED_MAX);
      sawAny = true;
      if (cursor > highestCursor) highestCursor = cursor;

      SIoTCommand command;
      uint64_t seq = 0;
      if (nonceLen == (int)SIOT_NONCE_BYTES && sealedLen > 0 &&
          openCommand(nonce, sealed, (size_t)sealedLen, plain, &seq, &command) && seq > mark) {
        /* The mark moves first. If the side effect then crashes the board, the
           command is lost rather than repeated, which is the safe direction for
           a physical action. A device whose action is idempotent loses nothing
           by this ordering either. */
        if (!commitCommandSeq(seq)) {
          fail("the command mark could not be committed to flash; not running the command");
          sodium_memzero(plain, SEALED_MAX);
          free(sealed);
          free(plain);
          free(sealedText);
          return SIoTStatus::StorageFailure;
        }
        mark = seq;
        if (handler != nullptr) handler(command);
      }
      sodium_memzero(plain, SEALED_MAX);
    }
    cursorAt = next;
  }
  free(sealed);
  free(plain);
  free(sealedText);

  if (!sawAny) {
    error_ = "";
    return SIoTStatus::Ok;
  }

  /* Ack everything seen, including what was skipped or would not open: it has
     been consumed either way, and leaving it queued would re-deliver it forever. */
  uint8_t ackMessage[SIOT_DEVICE_ID_BYTES + 8];
  memcpy(ackMessage, deviceId_, SIOT_DEVICE_ID_BYTES);
  for (int i = 0; i < 8; i += 1) {
    ackMessage[SIOT_DEVICE_ID_BYTES + i] = (uint8_t)((highestCursor >> (56 - 8 * i)) & 0xff);
  }
  uint8_t signature[SIOT_SIG_BYTES];
  if (crypto_sign_ed25519_detached(signature, nullptr, ackMessage, sizeof(ackMessage), signSecret_) != 0) {
    fail("signing the command ack failed");
    return SIoTStatus::CryptoFailure;
  }
  char sigText[89];
  b64urlEncode(signature, SIOT_SIG_BYTES, sigText);

  char body[160];
  snprintf(body, sizeof(body), "{\"up_to\":\"%llu\",\"sig\":\"%s\"}",
           (unsigned long long)highestCursor, sigText);

  WiFiClientSecure ackTls;
  ackTls.setCACert(caCertPem_);
  ackTls.setTimeout(HTTP_TIMEOUT_MS / 1000);
  char ackUrl[220];
  snprintf(ackUrl, sizeof(ackUrl), "%s/siot/devices/%s/commands/ack", baseUrl_, deviceIdText_);
  HTTPClient ackHttp;
  ackHttp.setTimeout(HTTP_TIMEOUT_MS);
  ackHttp.setConnectTimeout(HTTP_TIMEOUT_MS);
  if (!ackHttp.begin(ackTls, ackUrl)) {
    fail("the server URL could not be parsed");
    return SIoTStatus::NetworkFailure;
  }
  ackHttp.addHeader("Content-Type", "application/json");
  const int ackCode = ackHttp.POST((uint8_t *)body, strlen(body));
  ackHttp.end();

  /* A lost ack is harmless: the commands come back next poll and the mark skips
     them. That is the at-least-once delivery the design plans for. */
  if (ackCode != 200) {
    fail("the command ack was not accepted; the commands will be offered again");
    return ackCode <= 0 ? SIoTStatus::NetworkFailure : SIoTStatus::Rejected;
  }
  error_ = "";
  return SIoTStatus::Ok;
}

SIoTStatus SIoTClient::post(const char *body) {
  WiFiClientSecure tls;
  /*
   * Pinned, not merely encrypted. A device has no user to notice a warning
   * page, so an unpinned device is one that will hand its records to whatever
   * answers on that address. The certificate itself is pinned rather than its
   * SPKI: `WiFiClientSecure` exposes no hook for a public-key hash, and
   * certificate rotation for pinned devices is a known open problem (design
   * 15.1) rather than something this library can solve on its own.
   */
  tls.setCACert(caCertPem_);
  tls.setTimeout(HTTP_TIMEOUT_MS / 1000);

  char url[160];
  snprintf(url, sizeof(url), "%s/siot/records", baseUrl_);

  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.setConnectTimeout(HTTP_TIMEOUT_MS);
  if (!http.begin(tls, url)) {
    fail("the server URL could not be parsed");
    return SIoTStatus::NetworkFailure;
  }
  http.addHeader("Content-Type", "application/json");

  const int code = http.POST((uint8_t *)body, strlen(body));

  if (code <= 0) {
    /* Negative codes are HTTPClient's own: no route, TLS refused, timed out.
       Every one of them is "try again later" rather than "this record is
       wrong", and the two must not be conflated. */
    /* Read before end(): ending the request tears down the TLS state the reason lives in. */
    char tlsReason[80] = "";
    const int tlsCode = tls.lastError(tlsReason, sizeof(tlsReason));
    failNetwork("could not reach the server", code, tlsCode, tlsReason);
    http.end();
    return SIoTStatus::NetworkFailure;
  }
  http.end();

  switch (code) {
    case 201:
      error_ = "";
      return SIoTStatus::Ok;
    case 400:
      fail("the server rejected the record as malformed: this library and that server disagree about the protocol");
      return SIoTStatus::Rejected;
    case 401:
      fail("the signature did not verify: this board's DEVICE_SECRET is not the one registered for this DEVICE_ID");
      return SIoTStatus::Rejected;
    case 404:
      deleted_ = true;
      fail("this DEVICE_ID is not registered: the device has been deleted, so uploads have stopped");
      return SIoTStatus::DeviceUnknown;
    case 409:
      fail("the server has already seen this seq: another board may be running the same credentials");
      return SIoTStatus::SequenceRefused;
    default:
      if (code >= 500) {
        fail("the server failed to handle the record");
        return SIoTStatus::ServerFailure;
      }
      fail("the server refused the record");
      return SIoTStatus::Rejected;
  }
}
