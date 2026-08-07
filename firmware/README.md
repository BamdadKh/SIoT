# Firmware

## `SIoT/`: the device library (Phase 5)

The reference implementation of `docs/protocol.md`. A sketch calls `addReading` and `send`;
the library reads its credentials from the `siot` NVS partition, derives both keys, keeps the
sequence, encrypts, signs and uploads. See `SIoT/README.md`, and `SIoT/examples/Temperature`
for a complete sketch.

```bash
arduino-cli compile --fqbn esp32:esp32:esp32 --libraries firmware firmware/SIoT/examples/Temperature
```

Depends on nothing outside the ESP32 core: mbedTLS for HKDF and AES-256-GCM, libsodium for
Ed25519, TinyCBOR for the payload.

## `esp32-provisioning/` — the provisioning listener (roadmap 4.5)

The board half of design 5.3 step 4. It accepts `DEVICE_ID` and `DEVICE_SECRET` over
USB serial and writes them to the dedicated `siot` NVS partition. No WiFi, no network
stack, no SIoT wire protocol. Flash it once to a new board, provision from the browser,
then flash the application firmware over the top: the credentials are in a data
partition, so `arduino-cli upload` does not touch them.

```bash
arduino-cli compile --fqbn esp32:esp32:esp32 --port COM6 --upload firmware/esp32-provisioning
```

The protocol is documented in the sketch header, and is the same one
`frontend/app/src/lib/provisioning-protocol.js` speaks from the other end. Both sides
have to agree on it, so change them together or not at all.

`partitions.csv` is a superset of the stock ESP32 4MB `default` table with one partition
added. Its offset is load-bearing: moving `siot` in a later revision orphans every board
already provisioned, because the bytes stay at the old address and the new table looks
straight past them.

### Verifying a board by hand

There is no reason to reach for a serial monitor in the normal flow, but the protocol is
plain text and answers one line per command, so a monitor at 115200 works:

```
SIOT HELLO              -> SIOT OK PROVISION/1
SIOT READ-ID            -> SIOT OK <device_id>   or   SIOT OK -
SIOT ERASE <device_id>  -> SIOT OK               or   SIOT ERR STALE <stored-id|->
```

`READ-ID` is the only read there is. Nothing reads `DEVICE_SECRET` back out, deliberately:
a board that would hand its secret to anyone who can reach the port is worse than one that
makes you type the value again.

`ERASE` takes the id it expects to find and refuses if that is not what is there, the same
compare-and-swap `WRITE` uses. There is no "erase whatever is on it" form: that would be a
command that wipes whichever board happens to be plugged in. It is for a board being retired
rather than reused, since provisioning over one already destroys the old credentials.

## `esp32/` — the dead spike

The original unencrypted HTTP button counter, kept only for reference. **It does not work
against this server.** Its `POST /button` endpoint is gone and the server is HTTPS-only.
It gets replaced wholesale by the Phase 5 library rather than repaired.
