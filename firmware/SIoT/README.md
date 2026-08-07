# SIoT, the ESP32 device library

Reads its credentials from NVS, encrypts and signs each reading, and uploads records the
server stores without being able to read them. The sketch author writes `addReading` and
`send`, and never touches crypto (design Section 6).

```cpp
#include <SIoT.h>

SIoTClient siot;

void setup() {
  WiFi.begin(SSID, PASSWORD);
  // ... wait for a connection ...
  siot.setServer("https://192.168.1.20:3030", SERVER_CERT);
  siot.begin();                       // reads NVS, derives keys, advances boot_epoch
}

void loop() {
  siot.addReading("temp_c", 21.5);
  siot.addReading("heater", false);
  siot.send();
  delay(30000);
}
```

`examples/Temperature` is the whole of it, with the three values you have to fill in.

## Installing

Not published anywhere. Point `arduino-cli` at the folder that contains it:

```bash
arduino-cli compile --fqbn esp32:esp32:esp32 --libraries firmware firmware/SIoT/examples/Temperature
arduino-cli upload  --fqbn esp32:esp32:esp32 --port COM6      firmware/SIoT/examples/Temperature
```

Or symlink `firmware/SIoT` into your Arduino `libraries/` directory for the IDE.

**Your sketch needs `partitions.csv`.** Copy the one from `firmware/esp32-provisioning`
beside your `.ino`. It is the stock 4 MB table with one partition inserted, and without it
the credentials are sitting at an address your image's partition table does not describe,
so `begin()` reports `NotProvisioned` on a board that is perfectly well provisioned.

## Before a board will do anything

1. Flash `firmware/esp32-provisioning` and provision from the SIoT web client. That writes
   `DEVICE_ID` and `DEVICE_SECRET` into the dedicated `siot` NVS partition.
2. Flash your sketch over the top. Uploading writes the bootloader, the partition table and
   the app image and touches no data partition, so the credentials survive by construction.
   That is the "decoupled from the firmware image" property design 5.3 claims, and it is only
   true because the credentials are not in the image.

`begin()` takes no credentials and there is no API to pass any. On the supported path the
device already has them, which is the entire point of provisioning over a wire.

## What it depends on

Nothing that is not already in the ESP32 Arduino core:

| | |
| --- | --- |
| mbedTLS | HKDF-SHA256, and AES-256-GCM on the ESP32's AES accelerator |
| libsodium | Ed25519, seed-derived keypair and detached signatures |
| TinyCBOR | the `{ t, r }` payload |

All three are on the core's default include and link lines, so there is nothing to install
and no vendored crypto compiled in. Same reasoning as `backend/src/lib/ed25519.ts` using
Node's own Ed25519: the platform ships an audited implementation, and a second copy is a
second thing to get wrong.

## `boot_epoch`, the one thing that must not be lost

`seq = (boot_epoch << 32) | msg_counter`, and the nonce is a function of `seq` and nothing
else. A device that forgets `boot_epoch` restarts at 1, repeats a `seq`, and reuses a nonce,
which in AES-GCM leaks the XOR of two plaintexts and the authentication subkey. So:

- It lives in the `siot` partition, **not** the application's own NVS, where a
  `Preferences.clear()` or an `nvs_flash_erase()` in a factory-reset routine would reach it.
- `begin()` increments it, writes it, and **reads it back** before returning. A crash between
  the write and the first record skips an epoch, which costs nothing; the other order would
  repeat one.
- `SIOT ERASE` in the provisioning sketch deliberately leaves it behind. A counter is not a
  secret, and a board erased and later re-provisioned for the same device keeps a sequence
  that only moves forward.

If `begin()` cannot commit it, it fails and the device produces no records at all. That is
the intended behaviour: no telemetry is a great deal better than nonce reuse.

## Failures, and which ones to retry

`send()` returns a `SIoTStatus`. The distinction that matters to a battery is between a
record that is wrong and a record that was unlucky:

| Status | Retry? |
| --- | --- |
| `NetworkFailure`, `ServerFailure` | Yes. `send()` already retries these internally with backoff. |
| `Rejected` (400/401) | No. The record is wrong and will be wrong identically forever. |
| `DeviceUnknown` (404) | **No, and stop.** The device has been deleted. Latched: further sends fail immediately without touching the radio. |
| `SequenceRefused` (409) | No. The server has seen this `seq`; suspect two boards running one set of credentials. |
| `NotProvisioned`, `StorageFailure` | No. Nothing to do at runtime. |

Retries re-send the **same bytes**, never a rebuilt record. An identical record at an
identical `seq` is the same record; a fresh plaintext at that `seq` would reuse the nonce.

There is no store-and-forward buffer in v1. A record that cannot be delivered is dropped and
the counter has moved on, leaving a gap in `seq` that the owner's client surfaces as possible
missing data rather than smoothing over.

## Other transports

`buildRecord()` hands back the `POST /records` body without sending it, for a device on LoRa,
a cellular modem or a wired uplink. Everything that matters happens there; `send()` is that
plus an HTTP client. The body holds only ciphertext, a signature and public identifiers, so
it is safe to log or forward.

## The certificate is not optional

`setServer()` takes a PEM to pin. A phone has somebody to notice a warning page; a sensor in
a greenhouse does not, so an unpinned device hands its records to whatever answers on that
address. For the dev server that is `backend/certs/dev-cert.pem`, self-signed and therefore
its own root. Regenerating it means reflashing every device that pinned it.

**Deviation from roadmap 5.6, stated plainly:** the item asks for an SPKI pin and this pins
the certificate. `WiFiClientSecure` exposes no hook for a public-key hash, and there is no
supported way to reach into the handshake for one from Arduino. Certificate rotation for
pinned devices is a known open problem (design 15.1) rather than something this library can
solve; pinning the certificate is strictly narrower than pinning its SPKI, so this errs
towards refusing rather than accepting.

## What it will not do

It derives both keys at `begin()` and zeroes `DEVICE_SECRET` immediately. There is no
accessor for the signing key, no way to sign an arbitrary message, no way to decrypt a
record, and no command that reads the secret back out. A device only ever writes.

`docs/protocol.md` is the byte-level contract this implements, with test vectors. Anything
that reproduces them is accepted by the server on exactly the same terms as this library.
