# SIoT device wire protocol, v1

**What a device has to do to produce a record this server will accept.**

This is the interoperability contract. The ESP32 library in `firmware/` is the reference
implementation and the only one shipped, but it is not privileged: the server verifies a
signature, checks a sequence number, checks a nonce, and stores an opaque blob. It has no
notion of a blessed client and nothing to whitelist, because nothing is being trusted. A
Raspberry Pi, an nRF52, an STM32 or a Python script that produces conforming records is
accepted on exactly the same terms.

Section numbers in the form `design 7.2` refer to `SIoT_Design_Document.md`, which is the
reasoning behind everything here. This document is the byte-level form of it.

---

## 0. The shape of the thing

```
DEVICE_SECRET (32B)
   ├── HKDF-SHA256, info = "siot/device/data/v1"  ──> device_data_key (32B)
   └── HKDF-SHA256, info = "siot/device/sign/v1"  ──> ed25519_seed (32B) ──> keypair

seq (uint64)  = (boot_epoch << 32) | msg_counter          boot_epoch is persisted
nonce (12B)   = 0x00000000 || seq (8B big-endian)
AAD (26B)     = version(1) || DEVICE_ID(16) || record_type(1) || seq(8)
plaintext     = CBOR { t, r }
ciphertext    = AES-256-GCM(device_data_key, nonce, plaintext, AAD)
sig (64B)     = Ed25519(ed25519_priv, AAD || nonce || ciphertext)

POST /records { device_id, seq, nonce, ciphertext, sig }      all base64url but seq
```

Nothing in that chain requires a random number generator, a real-time clock, or any
server round trip. That is deliberate: a device that has just been power-cycled in a
greenhouse has none of the three reliably.

---

## 1. Credentials

A device is two values and everything else is derived from them:

| Value | Size | Where it lives |
| --- | --- | --- |
| `DEVICE_ID` | 16 bytes | Plaintext. The server's lookup key, and the only part of a device it is ever told. |
| `DEVICE_SECRET` | 32 bytes | The owner's encrypted vault, and the device. Never sent to the server, ever. |

Both are generated in the owner's browser when the device is added (design 5.1). There are
two ways to get them onto hardware:

- **The guided path**: Chromium's Web Serial writes them into a dedicated NVS partition on
  an ESP32. Nothing touches the clipboard and nothing goes into a firmware image.
- **Reveal credentials** (design 5.3.1): a deliberate control on the device's own page that
  shows both values as base64url. This is the path for everything that is not an ESP32, and
  it is an escape hatch rather than a second supported flow. Past it, the guarantees in the
  design document stop: how the values are stored on your hardware, whether they survive a
  firmware update, and what stops them being written over a board that already carries a
  working device are all yours to arrange.

A `DEVICE_SECRET` that leaks is the whole device: it reads every record that device has ever
uploaded and signs new ones the server accepts as genuine. Rotating it means re-provisioning
with a new secret, and the old records stay readable only to whoever still holds the old one
(design 9.3).

---

## 2. Key derivation

```
device_data_key = HKDF-SHA256(ikm = DEVICE_SECRET, salt = "", info = "siot/device/data/v1", L = 32)
ed25519_seed    = HKDF-SHA256(ikm = DEVICE_SECRET, salt = "", info = "siot/device/sign/v1", L = 32)
```

- **The salt is empty**, and that is not an omission. HKDF's salt exists to extract entropy
  from non-uniform input keying material, and `DEVICE_SECRET` is 32 bytes of CSPRNG output
  already. RFC 5869 section 3.1 covers this case explicitly.
- **The labels are a wire format, not naming.** They are ASCII, with no trailing NUL, and
  both sides compute them: the browser derives `sign_pub` from the same seed to register it.
  A port that invents an "equivalent" label produces a device whose records nothing can open
  and whose signatures nothing accepts. There is no negotiation step that would catch it.
- The signing keypair is **pure Ed25519** (RFC 8032), seed-derived: the 32-byte seed is the
  private key, and the public key is its standard expansion. Not Ed25519ph, not Ed25519ctx.
  Those derive the identical public key and then fail verification, which is a bad afternoon.

`device_data_key` is the read key and is what a grant hands to another device (design 9).
`ed25519_seed` is signing authority and never leaves the device: the browser derives the
public half at provisioning time and zeroes the seed immediately.

---

## 3. Sequence numbers

```
boot_epoch  uint32, PERSISTED, incremented once per boot before any record is produced
msg_counter uint32, RAM only, zero at boot, incremented once per record
seq         uint64 = (boot_epoch << 32) | msg_counter
```

**Persisting `boot_epoch` is the one requirement a port cannot trade away.** The nonce is a
function of `seq` and nothing else, so a device that forgets `boot_epoch` and restarts at 1
repeats a `seq`, and repeating a `seq` under a fixed `device_data_key` is nonce reuse. Nonce
reuse in GCM does not degrade the ciphertext gracefully: it leaks the XOR of two plaintexts
and, worse, the authentication subkey, which turns forgery from impossible into arithmetic.

Where it is persisted is the porter's choice (NVS, a file, an EEPROM cell, a counter in an
RTC domain that survives power loss). The rules:

- Increment and **commit it to storage before producing the first record of that boot**, not
  after. A crash between the two must skip a `boot_epoch`, never repeat one.
- Skipping is free. `seq` has to be strictly increasing, not contiguous, and a reboot already
  produces a jump of up to 2^32.
- Do the arithmetic in a real 64-bit integer. `boot_epoch` past 2^21 puts `seq` outside the
  range a double represents exactly, and a language that silently used one produces a `seq`
  the server accepts and a nonce nothing can reproduce. The second published vector is there
  to catch exactly this.

The server enforces `seq > last_seq` and nothing else, so a `msg_counter` that wraps within a
boot (4.3 billion records) has to reboot rather than wrap.

---

## 4. Nonce

```
nonce (12B) = 0x00000000 || seq (8 bytes, big-endian)
```

96 bits, which is GCM's native width, so no derivation or truncation happens inside the
cipher. The four leading zero bytes are reserved and MUST be zero: the server recomputes the
whole nonce from `seq` and rejects anything else (check 3), so there is no room to smuggle
data there.

---

## 5. AAD

```
AAD (26B) = version(1) || DEVICE_ID(16) || record_type(1) || seq(8, big-endian)
version     = 0x01     this protocol version
record_type = 0x00     reserved for per-schema record types; 0 for every v1 record
```

`version` and `record_type` do not appear in the request body. Design 7.3's own example body
carries only `{ device_id, seq, nonce, ciphertext, sig }`, so both sides rebuild the AAD from
these two constants plus the `device_id` and `seq` that are on the wire. A port that puts
them on the wire, or that reads them from it, will not interoperate.

The AAD is authenticated and **not** encrypted, so everything in it is something the server
sees. That is the reason `record_type` stays constant: a distinguishable "this is an alert"
record is a labelled event log, and a smoke alarm or a door sensor emitting one at a known
moment tells the server precisely what design 5.5 refuses to let device names tell it. Record
types that matter to a dashboard go **inside** the ciphertext.

Binding `DEVICE_ID` and `seq` into the AAD is what stops a server relocating a valid record
onto another device or into another sequence position: the bytes are authentic, the AAD no
longer matches, and GCM refuses to open it.

---

## 6. Payload

```
plaintext = CBOR { "t": <uint>, "r": { <reading name>: <scalar>, ... } }
```

- `t` is the device's own timestamp, unsigned, **seconds since the Unix epoch, UTC**. Send `0`
  if the device does not know the time; a client renders that as "the device has no clock"
  rather than as 1970. `t` is authenticated but comes from a clock nothing verifies, so it is
  never the ordering key: `seq` is (design 7.1), and an exported file labels the two
  differently for that reason.
- `r` is a map of reading names to scalars. Names are text strings. Values are integers,
  floats, text strings, booleans, or null.

CBOR (RFC 8949), in a deliberately small profile. Both the reference encoder and the client
decoder accept only:

| Allowed | Refused |
| --- | --- |
| unsigned and negative integers, to the full 64-bit range | byte strings |
| floats at half, single or double width | tags, of any number |
| text strings, definite length | indefinite lengths |
| arrays and maps, definite length | `undefined` and other simple values |
| `true`, `false`, `null` | duplicate or non-text map keys |

The reference encoder emits deterministic CBOR (RFC 8949 section 4.2): shortest-form heads,
and map keys sorted by length then bytes. **A device does not have to.** Nothing verifies the
encoding, because the signature covers whatever bytes the device actually produced. It
matters only in that the published vectors below assume it; if your encoder orders keys
differently, your ciphertext will differ from the vector while still being perfectly valid.

Keep records small. There is a 4 KiB ceiling on `ciphertext` at the server, and a payload
whose *length* varies with what it says is a payload whose length leaks what it says.

---

## 7. Signature

```
sig (64B) = Ed25519(ed25519_priv, AAD || nonce || ciphertext)
```

Concatenated in that order, with no separators and no length prefixes; the lengths are fixed
or implied. `ciphertext` includes the 16-byte GCM tag, as GCM's own output does.

The signature covers the AAD, so device identity, sequence position and record type are all
authenticated rather than merely asserted. It does not cover the request body's JSON: the
transport is irrelevant to it, which is what makes it verifiable after the fact from the
stored blob.

---

## 8. `POST /records`

Device-authenticated: no session, no cookie, no API key. Sending the record *is* the
authentication.

```http
POST /records
Content-Type: application/json

{
  "device_id":  "<16 bytes, base64url>",
  "seq":        "<decimal string, uint64>",
  "nonce":      "<12 bytes, base64url>",
  "ciphertext": "<base64url, 17 bytes to 4 KiB>",
  "sig":        "<64 bytes, base64url>"
}
```

- **base64url, unpadded** (RFC 4648 section 5): `-` and `_`, no `=`. Never hex, anywhere in
  this API.
- **`seq` is a decimal string, not a number.** It is a uint64 and JSON numbers are doubles;
  a parser that reads `17179869184000007` as a number gets a different value back out.
- Unknown fields are a 400. The server does not strip what it does not recognise, because a
  client that accidentally sends key material should be told, not quietly accommodated.

Success is `201` with an empty object. Every rejection:

| Status | Meaning | What to do |
| --- | --- | --- |
| `400` | Malformed body: a field missing, wrong length, not base64url, `seq` not a decimal string, an unknown field. | Fix the client. Never retry unchanged. |
| `400` | `nonce does not match 0x00000000 || seq` (check 3). | Your nonce construction is wrong. Never retry unchanged. |
| `401` | Signature does not verify against the registered `sign_pub` (check 1). | Your signing input, your key derivation, or your Ed25519 variant is wrong. Never retry unchanged. |
| `404` | Unknown `device_id`. | **The device has been deleted, or was never registered.** Stop. Retrying forever is a board flattening its battery against a server that will never accept it. |
| `409` | `seq` is not greater than the device's `last_seq` (check 2). | Advance `seq` and rebuild the record. Never resend the same one; that is the replay the check exists to refuse. |
| `413` | Body over the server's limit. | Send smaller records. |
| `5xx` | Server-side failure. | Retry with backoff. This is the one class that is genuinely transient. |

The three checks, in the order the server runs them (design 7.4), none of which decrypt
anything:

1. `Ed25519_verify(sign_pub, AAD || nonce || ciphertext, sig)`: is this really from that device?
2. `seq > last_seq[device_id]`: is it fresh, not a replay? Applied as a compare-and-swap in the
   same transaction as the insert, so two uploads racing for one device cannot both win.
3. `nonce == 0x00000000 || seq`: is the nonce well-formed and consistent with the claimed position?

A rejection writes nothing. A `409` in particular does not advance `last_seq`.

### Transport

HTTPS only; there is no plaintext listener and no redirect. The dev server uses a self-signed
certificate whose SPKI pin is printed by `npm run gen-cert` in `backend/`. A device should pin
something (the certificate, its SPKI, or a private CA), because a device has no user to
notice a warning page. Certificate rotation is an unsolved problem for pinned devices and is
tracked as design 15.1.

### Reading records back

`GET /devices/:device_id/records` is session-authenticated and owner-scoped: it is for the
owner's browser, not for a device. It returns `{ seq, nonce, ciphertext, created_at }` per
record, cursor-paginated by `after_seq` (exclusive), ascending, up to 500 per page.

`sig` is **not** returned, which is deliberate rather than an omission. The signature is what
authenticates a record to the *server*, which cannot decrypt it and therefore has nothing
else to go on. A reader holding `device_data_key` has something stronger: the record's own
GCM tag, over an AAD that binds the `DEVICE_ID` and the `seq`. A server cannot forge that,
cannot move a record to another device or another sequence position, and cannot alter a byte
of it, so it would be 64 bytes per record buying a check the decryption already made.
`created_at` is the server's arrival time and is only as trustworthy as the server; the
device's own `t` is inside the ciphertext, and the two are different claims.

A device that has been *granted* another device's data reads `GET /devices/:device_id/grants`
instead, which is public because a device holds no session (design 9.3). That is Phase 8 and
is out of scope for this document.

---

## 9. What a port must supply for itself

1. **A persisted `boot_epoch`.** Section 3. Not negotiable on any hardware.
2. **The exact HKDF labels**, byte for byte. Section 2.
3. **A correct AES-256-GCM and a correct pure Ed25519.** Use the platform's audited
   implementation rather than writing one.
4. **Somewhere to keep `DEVICE_SECRET`** that survives a firmware update, and the discipline
   not to put it in a source file or an image.
5. **Retry that distinguishes a 404 from a network drop.** A deleted device must stop, not
   retry forever.

And one thing to be aware of rather than to implement: the server sees when every record
arrives, from what address, and how large it is. That metadata is acknowledged and unfixed
(design 13.1). A device reporting on a fixed schedule leaks less than one that reports when
something happens.

---

## 10. Test vectors

`docs/vectors/records-v1.json` holds the machine-readable form. **A port that cannot
reproduce these is broken**, and finding that out here beats finding it out from a server
rejection with no detail in it.

They are generated from the shipped client modules by `frontend/scripts/generate-vectors.js`
and re-derived from scratch on every `npm test` by `frontend/test/protocol-vectors.test.js`,
so they cannot drift from the implementation or from this document.

> The `DEVICE_SECRET` below is public. Everything derived from it, including the signing key,
> is in this repository. Never provision a real device with it.

```
DEVICE_SECRET     000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
DEVICE_ID         a0a1a2a3a4a5a6a7a8a9aaabacadaeaf        (oKGio6SlpqeoqaqrrK2urw)

device_data_key   50fb1f1509acecad558bccf016b474f91cfeebf61586725ee63a84c15808f08a
ed25519_seed      9595ad886769577a2a4f6a36ef6af3fafb2ca91b944c644a51ad5be24a3ce5bc
sign_pub          2246553f1fcf9353e3ca5c7e07989e96252060aacab0eaf8df7df93b4e7130ff
```

**Vector 1**, the first record of the first boot, the smallest `seq` a device can legally
produce:

```
boot_epoch    1
msg_counter   0
seq           4294967296
payload       { "t": 1786000000, "r": { "temp_c": 21.5, "humidity": 48, "heater": false } }

CBOR          a26172a366686561746572f46674656d705f63fb40358000000000006868756d6964697479
              183061741a6a743280
nonce         000000000000000100000000
AAD           01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000100000000
ciphertext    9b6ec7a3916cea07650ca8fb5bc46e18150ff5398c13d90ef076df9e8d5518e55ce4325ffe
              836ee1cdd5f99381642798a6062f71312dacbaed0cbe5a65d7
sig           21b06a516f497bae7277d4898c4c55e64c743e87dbf665cfcf4d794b9cd6d6b24290a5bef1
              529ff91141df5f66ec2d978d5635778dc64971f7663ae1a02b1b0e
```

**Vector 2**, a `boot_epoch` past 2^21, where `seq` stops being exactly representable as a
double. If your client matches vector 1 and not this one, look at the type you compose `seq`
with:

```
boot_epoch    4000000
msg_counter   7
seq           17179869184000007
payload       { "t": 1786003600, "r": { "temp_c": -3.25, "humidity": 91, "heater": true } }

CBOR          a26172a366686561746572f56674656d705f63fbc00a0000000000006868756d6964697479
              185b61741a6a744090
nonce         00000000003d090000000007
AAD           01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00003d090000000007
ciphertext    e23420721536e6e5553a175c79319c7bc04005c9d875db8106094ac8b4106dc9195eb95f91
              aecf44dd3c61d8043cf05eecb383666c5a4f665ac133a14c53
sig           eda32ffa4c49a5261bca278efe406d2cf2e4052daf1b6fbaab89789ee164d0bcd6d7906cfa
              de3d29d87d400dcd617d2475d5f9f71f5fcf0ce12887cd4d501c02
```

The JSON file also carries the exact `POST /records` body for each, so a port can diff its
own request against a known-good one rather than against a description of one.

### Checking a port against them, in order

Work down the chain; each step's output is the next step's input, so the first mismatch is
the bug.

1. `device_data_key` and `sign_pub` from `DEVICE_SECRET`. A mismatch is the HKDF labels, the
   empty salt, or an Ed25519 variant that is not the pure one.
2. `seq` from `boot_epoch` and `msg_counter`. A mismatch on vector 2 only is a 64-bit
   arithmetic problem.
3. `nonce` and `AAD`. These are pure byte layout; a mismatch is an endianness or ordering bug.
4. The CBOR payload. A mismatch here does not necessarily mean a bug (see section 6 on
   ordering), but it does mean the ciphertext below will not match either, so pin your
   encoder to the published bytes while testing the rest.
5. `ciphertext`. With a fixed key, nonce, AAD and plaintext, AES-256-GCM is deterministic, so
   this either matches exactly or something above it does not.
6. `sig`. A mismatch after a matching ciphertext is the signing input: it is
   `AAD || nonce || ciphertext`, not the payload and not the JSON body.

These two vectors have been posted verbatim to a running server: both accepted with `201`,
the replay of the first refused with `409`, a signature with one bit flipped refused with
`401`, and both blobs read back and decrypted to the payloads above.
