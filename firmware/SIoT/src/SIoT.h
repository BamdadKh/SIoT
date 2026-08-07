/*
 * SIoT device library for ESP32 (design Section 6, roadmap Phase 5).
 *
 * The reference implementation of the wire protocol in `docs/protocol.md`. A
 * sketch declares readings and calls `send()`; everything between that and the
 * server is here, and none of it is the sketch author's problem:
 *
 *   credentials      read from the dedicated `siot` NVS partition, never passed in
 *   key derivation   HKDF-SHA256 under the two published labels
 *   sequencing       a persisted boot_epoch and a RAM message counter
 *   nonce            0x00000000 || seq, so nonce reuse is structurally impossible
 *   encryption       AES-256-GCM, hardware accelerated, with the design 7.3 AAD
 *   signing          Ed25519 over AAD || nonce || ciphertext
 *   upload           POST /records over TLS with a pinned certificate
 *
 * `begin()` takes no credentials, and that is the point of the whole
 * provisioning path (design 6): on the supported path the device already has
 * them, written over USB by a tool the owner was looking at, so they were never
 * in a firmware image, in the clipboard, or in source control. Reflashing this
 * sketch as many times as you like leaves them where they are, because they live
 * in a data partition the application never writes.
 *
 * ## Dependencies: none beyond the core
 *
 * mbedTLS (HKDF, AES-256-GCM), libsodium (Ed25519) and TinyCBOR are all already
 * on the ESP32 Arduino core's include and link lines. Nothing here is vendored
 * and no third-party crypto is compiled in, for the same reason
 * `backend/src/lib/ed25519.ts` uses Node's own: the platform ships an audited
 * implementation, and a second copy is a second thing to get wrong.
 *
 * ## What this library will not do
 *
 * It never reads `DEVICE_SECRET` back out to anything: it derives the two keys
 * at `begin()` and zeroes the secret immediately. There is no accessor for the
 * signing key, no way to sign an arbitrary message, and no way to decrypt a
 * record. A device only ever writes.
 */

#ifndef SIOT_H
#define SIOT_H

#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

/** Wire constants. These are the protocol, not preferences: see docs/protocol.md. */
static const size_t SIOT_DEVICE_ID_BYTES = 16;
static const size_t SIOT_DEVICE_SECRET_BYTES = 32;
static const size_t SIOT_KEY_BYTES = 32;
static const size_t SIOT_NONCE_BYTES = 12;
static const size_t SIOT_AAD_BYTES = 26;
static const size_t SIOT_TAG_BYTES = 16;
static const size_t SIOT_SIG_BYTES = 64;

/** base64url of a DEVICE_ID, unpadded, plus a terminator. */
static const size_t SIOT_DEVICE_ID_TEXT_BYTES = 23;

/**
 * Per-record limits, chosen to keep every buffer in this library static.
 *
 * A record is one moment's readings, not a batch: the server caps `ciphertext`
 * at 4 KiB, and a payload whose length varies with what it says is a payload
 * whose length leaks what it says (design 13.1).
 */
static const size_t SIOT_MAX_READINGS = 12;
static const size_t SIOT_READING_NAME_MAX = 24;
static const size_t SIOT_READING_TEXT_MAX = 32;
static const size_t SIOT_PAYLOAD_MAX = 512;

/**
 * Enough for a full payload once base64url has expanded the ciphertext by a
 * third, plus the identifiers, the signature and the JSON around them. A
 * caller passing its own buffer to `buildRecord` wants at least this much.
 */
static const size_t SIOT_RECORD_BODY_MAX = 1024;

/** What `send()` reports. Everything but `Ok` leaves the readings buffer cleared. */
enum class SIoTStatus : uint8_t {
  /** Accepted and stored. */
  Ok,
  /** `begin()` has not run, or it failed. */
  NotBegun,
  /** The `siot` partition holds no credentials. Provision the board first. */
  NotProvisioned,
  /** NVS would not read or write. `boot_epoch` could not be advanced safely. */
  StorageFailure,
  /** Key derivation, encryption or signing failed. Should be unreachable. */
  CryptoFailure,
  /** No readings were added, so there is nothing to send. */
  NoReadings,
  /** The encoded payload did not fit. Send fewer or shorter readings. */
  PayloadTooLarge,
  /** WiFi down, TLS refused, no route, timeout. Transient: try again later. */
  NetworkFailure,
  /**
   * The server refused the record itself: a 400 or a 401. The record is wrong,
   * not unlucky, and resending it unchanged will fail identically forever.
   */
  Rejected,
  /**
   * 404: this `DEVICE_ID` is not registered. The device has been deleted, or
   * never registered. Latched, so subsequent sends fail immediately without
   * touching the radio: a deleted device that retries forever is a board
   * flattening its battery against a server that will never accept it.
   */
  DeviceUnknown,
  /** 409: the server has already seen this `seq`. Should be unreachable. */
  SequenceRefused,
  /** A 5xx. The server is having a bad day; this one is worth retrying. */
  ServerFailure,
};

/** For logging. Returns a static string; never null. */
const char *SIoTStatusName(SIoTStatus status);

class SIoTClient {
 public:
  SIoTClient();

  /**
   * Points the client at a server and pins what it will talk to.
   *
   * `caCertPem` is the certificate to trust, as a PEM string, and it is not
   * optional: a device has no user to notice a warning page, so an unpinned
   * device is a device that will talk to whatever answers. For the dev server
   * that is `backend/certs/dev-cert.pem`, which is self-signed and therefore
   * its own root.
   *
   * Must be called before `begin()`. Neither string is copied, so both have to
   * outlive the client: a `const char[]` at file scope, which is what a sketch
   * naturally writes.
   *
   * @param baseUrl e.g. "https://192.168.1.20:3030", no trailing slash.
   */
  void setServer(const char *baseUrl, const char *caCertPem);

  /**
   * Reads the credentials, derives both keys, and advances `boot_epoch`.
   *
   * **`boot_epoch` is committed to flash before this returns**, and before any
   * record can be produced. A crash between the write and the first record
   * skips an epoch, which is free; the other order would repeat one, and a
   * repeated `seq` under a fixed key is nonce reuse (design 7.2). That is the
   * one failure in this library that would break the cryptography rather than
   * inconvenience someone, which is why it happens here and not lazily.
   *
   * @return false if the board is unprovisioned or storage failed. `lastError()`
   *         says which.
   */
  bool begin();

  /** Readings for the next record. False if the buffer is full or the name is too long. */
  bool addReading(const char *name, double value);
  bool addReading(const char *name, int value);
  bool addReading(const char *name, long long value);
  bool addReading(const char *name, bool value);
  bool addReading(const char *name, const char *value);

  /** Drops any readings added since the last send. */
  void clearReadings();

  /**
   * Encrypts, signs and uploads one record, then clears the readings.
   *
   * The device's own timestamp comes from `time()` and is sent as 0 when the
   * clock has never been set, which a client renders as "this device has no
   * clock" rather than as 1970. `seq` is the authoritative order either way
   * (design 7.1), so a device with no NTP is fully functional.
   *
   * On a transient failure the *same bytes* are retried, up to `attempts`. That
   * is safe and re-encrypting is not: an identical record at an identical `seq`
   * is the same record, while a new plaintext at the same `seq` would reuse the
   * nonce. If every attempt fails the record is dropped and the counter has
   * moved on, leaving a gap in `seq` that the owner's client surfaces as
   * possible missing data rather than silently smoothing over.
   */
  SIoTStatus send(uint8_t attempts = 3);

  /**
   * Builds one record and hands back the `POST /records` body, without sending
   * it. Advances the sequence and clears the readings exactly as `send()` does.
   *
   * This is the seam design 6.1 asks for: WiFi is one transport, and a device on
   * LoRa, a cellular modem driven over AT commands, or a wired uplink still
   * wants the record built correctly by code that has been checked. Everything
   * that matters happens here; `send()` is this plus an HTTP client.
   *
   * The body is JSON containing only ciphertext, a signature and public
   * identifiers, so it is safe to log or forward. There is deliberately no way
   * to get the plaintext, the keys or the signing seed back out of this object.
   *
   * A record built and never delivered leaves a gap in `seq`, the same as a
   * failed upload: the owner's client surfaces that as possible missing data
   * rather than smoothing over it. What must not happen is a second record
   * built at the same `seq`, which is why this advances the counter rather than
   * letting a caller decide when to.
   *
   * @param out       receives a NUL-terminated JSON body.
   * @param capacity  size of `out`; about 1 KiB is comfortable for 12 readings.
   * @param written   optional, receives the body length.
   */
  SIoTStatus buildRecord(char *out, size_t capacity, size_t *written = nullptr);

  /** True once a 404 has latched. Cleared only by a reboot or `begin()` again. */
  bool isDeleted() const { return deleted_; }

  /** Human-readable detail for the last failure. Static string, never null. */
  const char *lastError() const { return error_; }

  /** This boot's epoch, after `begin()` advanced it. */
  uint32_t bootEpoch() const { return bootEpoch_; }

  /** Records produced this boot. The next record's `msg_counter`. */
  uint32_t messageCount() const { return msgCounter_; }

  /** The device's public identifier, base64url. Safe to print: the server has it. */
  const char *deviceId() const { return deviceIdText_; }

 private:
  struct Reading {
    char name[SIOT_READING_NAME_MAX + 1];
    enum class Kind : uint8_t { Double, Int, Bool, Text } kind;
    double number;
    long long integer;
    bool flag;
    char text[SIOT_READING_TEXT_MAX + 1];
  };

  bool loadCredentials(uint8_t *secret);
  bool advanceBootEpoch();
  bool addNamed(const char *name, Reading **slot);
  size_t encodePayload(uint8_t *out, size_t capacity, uint32_t timestamp);
  void buildAad(uint8_t *aad, uint64_t seq) const;
  void buildNonce(uint8_t *nonce, uint64_t seq) const;
  SIoTStatus post(const char *body);
  void fail(const char *message);

  const char *baseUrl_;
  const char *caCertPem_;

  bool ready_;
  bool deleted_;
  const char *error_;

  uint8_t deviceId_[SIOT_DEVICE_ID_BYTES];
  char deviceIdText_[SIOT_DEVICE_ID_TEXT_BYTES];
  uint8_t dataKey_[SIOT_KEY_BYTES];
  /** libsodium's expanded secret key: seed || public key. Never leaves this object. */
  uint8_t signSecret_[64];

  uint32_t bootEpoch_;
  uint32_t msgCounter_;

  Reading readings_[SIOT_MAX_READINGS];
  size_t readingCount_;
};

#endif  // SIOT_H
