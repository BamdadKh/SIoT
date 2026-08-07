/*
 * SIoT provisioning listener (roadmap 4.5, design 5.3 step 4 and 5.4).
 *
 * This is not application firmware and deliberately shares nothing with it. It
 * does one job: accept DEVICE_ID and DEVICE_SECRET over the USB serial line and
 * put them in the dedicated `siot` NVS partition. No WiFi, no network stack, no
 * SIoT wire protocol. The Phase 5 library reads what this writes and never
 * writes it itself.
 *
 * Keeping them apart is the point of the flow. The credentials are written once,
 * over a physical wire, by a tool the user is looking at; the application is then
 * flashed over the top as many times as they like without the secret ever being
 * in the image, in the clipboard, or in source control (design 5.3).
 *
 * ## The protocol
 *
 * Line oriented ASCII at 115200 baud. One command per line terminated by \n, one
 * response line per command. Anything not beginning with `SIOT ` is ignored, so
 * ROM bootloader chatter and a stray serial monitor cannot be mistaken for a
 * command, and the tool applies the same rule in the other direction.
 *
 *   SIOT HELLO
 *     -> SIOT OK PROVISION/1
 *     Confirms this sketch is on the other end. The user picks a port from a
 *     chooser the browser draws, and the port they pick may be a 3D printer.
 *
 *   SIOT READ-ID
 *     -> SIOT OK <device_id base64url>   an id is stored
 *     -> SIOT OK -                       blank board
 *
 *   SIOT WRITE <expected-id|-> <device_id> <device_secret>    all base64url
 *     -> SIOT OK
 *     -> SIOT ERR STALE <stored-id|->
 *     -> SIOT ERR ...
 *
 *   SIOT ERASE <expected-id>
 *     -> SIOT OK
 *     -> SIOT ERR STALE <stored-id|->
 *     Removes both values. Carries the same compare-and-swap `WRITE` does, for
 *     the same reason: a board swapped between the read and the erase must not
 *     be wiped on the strength of a check computed for a different one. There is
 *     deliberately no "erase whatever is there" form; a blank expectation is
 *     refused rather than treated as a wildcard.
 *
 * `WRITE` carries the id the tool believes is already on the board, and the
 * write only happens if that is still what is there: a compare-and-swap, the
 * same shape as the `vault_version` and `last_seq` swaps on the server. Design
 * 5.4 puts the overwrite decision in the tool, and it stays there (the tool has
 * the vault and therefore knows whether a stored id is *the user's*, which this
 * sketch cannot know). The swap is what makes that decision binding: between
 * READ-ID and WRITE a user can unplug one board and plug in another, and a
 * check whose answer was computed against the first board would then be applied
 * to the second. A blind write is one cable swap away from silently orphaning a
 * working device.
 *
 * ## What this deliberately cannot do
 *
 * There is no command that reads DEVICE_SECRET back out. The wire carries it in
 * one direction only. A read-back command would be convenient for testing and
 * would turn every provisioned board into a secret-extraction device for anyone
 * who can reach the port, which is a strictly worse trade than typing the value
 * again. The write verifies itself by comparing what NVS returns against what it
 * was given, in RAM, and reports only whether they matched.
 *
 * Nothing here is a defence against someone holding the board. Physical access
 * is the trust boundary this whole path is built on (design 5.3), and an
 * attacker with the board can read the flash directly. Flash encryption is the
 * answer to that and is roadmap 9.5.
 */

#include <Preferences.h>
#include <string.h>

/* The partition from partitions.csv, not the stock `nvs` the application owns.
   See that file for why the separation is load-bearing. */
static const char *NVS_PARTITION = "siot";
static const char *NVS_NAMESPACE = "siot";
static const char *KEY_ID = "id";
static const char *KEY_SECRET = "secret";

static const size_t DEVICE_ID_BYTES = 16;
static const size_t DEVICE_SECRET_BYTES = 32;

/* base64url of 16 bytes, unpadded. There is no matching constant for the secret
   because the secret is only ever decoded here, never encoded: nothing on this
   side needs a buffer to print it into, which is the property that keeps it from
   being printable at all. */
static const size_t ID_TEXT_LEN = 22;

/* The longest legal line is `SIOT WRITE ` + 22 + 1 + 22 + 1 + 43 = 100 bytes.
   The cap is generous but finite: an unterminated flood must not grow a buffer. */
static const size_t MAX_LINE_BYTES = 160;

static Preferences store;

static char line[MAX_LINE_BYTES + 1];
static size_t lineLen = 0;
static bool lineOverflowed = false;

/* --- base64url ----------------------------------------------------------- */

/* Hand-rolled rather than pulled from the core's libb64, which does padded
   standard base64 and would need the alphabet swapped and the padding stripped
   on both sides. Two fixed lengths and no streaming is a small enough job to own
   outright. base64url, never hex, matching the wire format everywhere else. */

static const char B64URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int b64urlValue(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

/* `out` must hold 4*ceil(len/3) + 1. */
static void b64urlEncode(const uint8_t *in, size_t len, char *out) {
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
}

/*
 * Decodes exactly `expected` bytes or fails. Length is checked before the
 * alphabet so a 15-byte id can never be accepted and then padded out to 16 by a
 * caller that assumed the buffer was filled.
 */
static bool b64urlDecodeExact(const char *in, uint8_t *out, size_t expected) {
  const size_t textLen = (expected * 4 + 2) / 3;  // unpadded
  if (strlen(in) != textLen) return false;

  uint32_t block = 0;
  int bits = 0;
  size_t o = 0;

  for (size_t i = 0; i < textLen; i++) {
    const int v = b64urlValue(in[i]);
    if (v < 0) return false;
    block = (block << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= expected) return false;
      out[o++] = (uint8_t)((block >> bits) & 0xFF);
    }
  }

  /* The trailing bits of an unpadded encoding must be zero. Without this check
     several different strings decode to the same 16 bytes, so a DEVICE_ID would
     stop being a canonical form of itself and the compare-and-swap below could
     be satisfied by a string the tool never sent. */
  if (bits > 0 && (block & ((1u << bits) - 1)) != 0) return false;

  return o == expected;
}

/* --- storage ------------------------------------------------------------- */

/*
 * Opened read-write even to read. A read-only open of a namespace that has never
 * been written fails, and a blank board is the ordinary case here rather than an
 * error worth a distinct code.
 */
static bool openStore() {
  return store.begin(NVS_NAMESPACE, false, NVS_PARTITION);
}

/* True if a well-formed id is stored. A wrong-length value counts as absent:
   nothing this sketch writes can produce one, so it is corruption, and treating
   it as "some other device" would refuse a write that is the way out of it. */
static bool loadStoredId(uint8_t *out) {
  if (store.getBytesLength(KEY_ID) != DEVICE_ID_BYTES) return false;
  return store.getBytes(KEY_ID, out, DEVICE_ID_BYTES) == DEVICE_ID_BYTES;
}

/* --- responses ----------------------------------------------------------- */

static void ok() {
  Serial.println("SIOT OK");
}

static void okWith(const char *value) {
  Serial.print("SIOT OK ");
  Serial.println(value);
}

static void err(const char *code, const char *detail = nullptr) {
  Serial.print("SIOT ERR ");
  Serial.print(code);
  if (detail != nullptr) {
    Serial.print(' ');
    Serial.print(detail);
  }
  Serial.println();
}

/* --- commands ------------------------------------------------------------ */

static void handleReadId() {
  if (!openStore()) {
    err("NVS", "could not open the siot partition");
    return;
  }

  uint8_t id[DEVICE_ID_BYTES];
  const bool present = loadStoredId(id);
  store.end();

  if (!present) {
    okWith("-");
    return;
  }

  char text[ID_TEXT_LEN + 1];
  b64urlEncode(id, DEVICE_ID_BYTES, text);
  okWith(text);
}

static void handleWrite(char *args) {
  char *expectedText = strtok(args, " ");
  char *idText = strtok(nullptr, " ");
  char *secretText = strtok(nullptr, " ");

  /* A fourth token means the tool sent something this version does not
     understand. Accepting it and ignoring the tail is how a later protocol
     revision gets silently half-applied. */
  if (expectedText == nullptr || idText == nullptr || secretText == nullptr ||
      strtok(nullptr, " ") != nullptr) {
    err("BAD-ARGS", "expected: WRITE <expected-id|-> <device_id> <device_secret>");
    return;
  }

  uint8_t id[DEVICE_ID_BYTES];
  if (!b64urlDecodeExact(idText, id, DEVICE_ID_BYTES)) {
    err("BAD-LENGTH", "device_id must be 16 bytes of base64url");
    return;
  }

  uint8_t secret[DEVICE_SECRET_BYTES];
  if (!b64urlDecodeExact(secretText, secret, DEVICE_SECRET_BYTES)) {
    err("BAD-LENGTH", "device_secret must be 32 bytes of base64url");
    return;
  }

  const bool expectBlank = (strcmp(expectedText, "-") == 0);
  uint8_t expected[DEVICE_ID_BYTES];
  if (!expectBlank && !b64urlDecodeExact(expectedText, expected, DEVICE_ID_BYTES)) {
    err("BAD-LENGTH", "expected-id must be 16 bytes of base64url or -");
    memset(secret, 0, sizeof(secret));
    return;
  }

  if (!openStore()) {
    err("NVS", "could not open the siot partition");
    memset(secret, 0, sizeof(secret));
    return;
  }

  uint8_t stored[DEVICE_ID_BYTES];
  const bool present = loadStoredId(stored);

  /* The compare-and-swap. `STALE` names what is actually on the board so the
     tool can say which device it found rather than only that it was surprised. */
  const bool matches = expectBlank ? !present
                                   : (present && memcmp(stored, expected, DEVICE_ID_BYTES) == 0);
  if (!matches) {
    char text[ID_TEXT_LEN + 1] = "-";
    if (present) b64urlEncode(stored, DEVICE_ID_BYTES, text);
    store.end();
    memset(secret, 0, sizeof(secret));
    err("STALE", text);
    return;
  }

  const bool wrote = store.putBytes(KEY_ID, id, DEVICE_ID_BYTES) == DEVICE_ID_BYTES &&
                     store.putBytes(KEY_SECRET, secret, DEVICE_SECRET_BYTES) == DEVICE_SECRET_BYTES;

  /* Read both back and compare in RAM before answering OK. A write that reports
     success it did not have sends someone away with a board that will never
     produce a decryptable record, and the failure surfaces days later as silence
     rather than here as an error. Nothing read back is ever printed. */
  bool verified = false;
  if (wrote) {
    uint8_t idBack[DEVICE_ID_BYTES];
    uint8_t secretBack[DEVICE_SECRET_BYTES];
    verified = store.getBytes(KEY_ID, idBack, DEVICE_ID_BYTES) == DEVICE_ID_BYTES &&
               store.getBytes(KEY_SECRET, secretBack, DEVICE_SECRET_BYTES) == DEVICE_SECRET_BYTES &&
               memcmp(idBack, id, DEVICE_ID_BYTES) == 0 &&
               memcmp(secretBack, secret, DEVICE_SECRET_BYTES) == 0;
    memset(secretBack, 0, sizeof(secretBack));
  }

  store.end();
  memset(secret, 0, sizeof(secret));

  if (!verified) {
    err("NVS", "the write did not read back");
    return;
  }
  ok();
}

/*
 * Retires a board: both values gone, nothing left in flash for the device that
 * used to live here (roadmap 4.9).
 *
 * `WRITE` already reclaims a board for a *new* device, so this is for the board
 * that is going in a drawer rather than into another project. It adds no
 * exposure `WRITE` does not already have (anyone who can reach this port can
 * already overwrite the credentials, which destroys them just as thoroughly),
 * and it means a retired board stops being a live DEVICE_SECRET sitting in
 * flash for a device that no longer exists.
 *
 * The expectation is required and `-` is not accepted. An erase with no
 * expectation would be a command that wipes whatever board happens to be
 * plugged in, which is precisely the shape the compare-and-swap exists to
 * refuse; and there is nothing to erase on a blank board anyway.
 */
static void handleErase(char *args) {
  char *expectedText = strtok(args, " ");
  if (expectedText == nullptr || strtok(nullptr, " ") != nullptr) {
    err("BAD-ARGS", "expected: ERASE <expected-id>");
    return;
  }

  uint8_t expected[DEVICE_ID_BYTES];
  if (!b64urlDecodeExact(expectedText, expected, DEVICE_ID_BYTES)) {
    err("BAD-LENGTH", "expected-id must be 16 bytes of base64url");
    return;
  }

  if (!openStore()) {
    err("NVS", "could not open the siot partition");
    return;
  }

  uint8_t stored[DEVICE_ID_BYTES];
  const bool present = loadStoredId(stored);
  if (!present || memcmp(stored, expected, DEVICE_ID_BYTES) != 0) {
    char text[ID_TEXT_LEN + 1] = "-";
    if (present) b64urlEncode(stored, DEVICE_ID_BYTES, text);
    store.end();
    err("STALE", text);
    return;
  }

  /* The secret goes first. If the two removals are interrupted between them, a
     board with an id and no secret is the recoverable state: it reads as
     occupied, so nothing overwrites it silently, and a re-erase or a WRITE
     finishes the job. The other order leaves a secret with no id, which reads
     as blank and would be quietly written over while still holding the old
     secret in flash. */
  const bool cleared = store.remove(KEY_SECRET) && store.remove(KEY_ID);

  /* Verified by reading back, the same way WRITE verifies itself: an API that
     returned success is not evidence that flash changed. */
  const bool verified = cleared && store.getBytesLength(KEY_ID) == 0 &&
                        store.getBytesLength(KEY_SECRET) == 0;
  store.end();

  if (!verified) {
    err("NVS", "the erase did not read back");
    return;
  }
  ok();
}

static void handleLine(char *text) {
  /* Everything that is not addressed to us is noise, not an error. The port is
     shared with the ROM bootloader's own output and with whatever a serial
     monitor left in the buffer. */
  if (strncmp(text, "SIOT ", 5) != 0) return;

  char *command = text + 5;
  char *space = strchr(command, ' ');
  char *args = nullptr;
  if (space != nullptr) {
    *space = '\0';
    args = space + 1;
  }

  if (strcmp(command, "HELLO") == 0) {
    okWith("PROVISION/1");
  } else if (strcmp(command, "READ-ID") == 0) {
    handleReadId();
  } else if (strcmp(command, "WRITE") == 0) {
    handleWrite(args == nullptr ? (char *)"" : args);
  } else if (strcmp(command, "ERASE") == 0) {
    handleErase(args == nullptr ? (char *)"" : args);
  } else {
    err("BAD-COMMAND", command);
  }
}

/* --- loop ---------------------------------------------------------------- */

void setup() {
  Serial.begin(115200);
  /* For a human with a serial monitor. The tool ignores it: it handshakes by
     sending HELLO and waiting for the reply, so it does not matter whether it
     opened the port before or after this line went out. */
  Serial.println("SIOT READY PROVISION/1");
}

void loop() {
  while (Serial.available() > 0) {
    const char c = (char)Serial.read();

    if (c == '\r') continue;

    if (c != '\n') {
      if (lineLen < MAX_LINE_BYTES) {
        line[lineLen++] = c;
      } else {
        lineOverflowed = true;
      }
      continue;
    }

    line[lineLen] = '\0';

    /* An over-long line is answered rather than silently truncated: a truncated
       WRITE would fail its length checks and report a confusing reason. */
    if (lineOverflowed) {
      err("TOO-LONG");
    } else if (lineLen > 0) {
      handleLine(line);
    }

    /* The line buffer held DEVICE_SECRET in the clear for the length of one
       command. Best effort, the same caveat the browser keyring carries: this
       zeroes the copy it knows about, not any the runtime made. */
    memset(line, 0, sizeof(line));
    lineLen = 0;
    lineOverflowed = false;
  }
}
