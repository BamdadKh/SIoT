# Hardening an ESP32 against someone holding it

> Roadmap 9.5, design 6.2. **Read the whole page before burning anything.** Every step that
> touches eFuses is permanent. There is no undo, no reset, and no support channel that can
> reverse it, because reversibility is exactly what an attacker holding the board would use.

## What this is for, and what it is not

SIoT's whole path to a board is physical: credentials go over USB, never over a network
(design 5.3). The cost of that choice is that the board itself is the trust boundary. Out of
the box, anyone who holds it and has a USB cable can dump the flash and read `DEVICE_SECRET`
from the `siot` partition. With that secret they can read everything the device ever
uploaded and sign records as it.

This page covers how to make that dump useless. It is for devices left somewhere other people
can reach: a sensor in a shared building, a board shipped to someone else. A board on your
own desk gains little and loses a lot of convenience.

None of this protects:

- a secret you revealed (design 5.3.1). That copy is on your computer now;
- the server's view of timing and sizes (design 13). That is metadata, not flash;
- a board running while an attacker probes it with fault injection or power analysis. That
  is outside the ESP32's own threat model, never mind this project's.

## The part that is easy to get wrong: flash encryption does not cover NVS

**Burning the flash-encryption fuses alone does not protect `DEVICE_SECRET`.** ESP32 flash
encryption covers the bootloader, the partition table, app partitions and any partition
flagged `encrypted`. NVS partitions are not compatible with that flag, so ESP-IDF leaves NVS
out of flash encryption and provides a separate mechanism, **NVS encryption**, for it. `siot` is an NVS partition. Without NVS
encryption it stays plaintext in a flash whose every other byte is encrypted, which is about
the worst way to spend a set of permanent fuses.

NVS encryption on the original ESP32 keeps its keys in a small `nvs_keys` partition, which
*is* flagged `encrypted`, so flash encryption protects the keys and the keys protect NVS.
That needs two things this project does not have yet:

1. **A partition table with an `nvs_keys` partition.** The current table
   (`firmware/esp32-provisioning/partitions.csv`) has none. Its own rule applies: never move
   `siot`; take the space from the end of `spiffs` instead. One 4 KB partition is enough.
2. **Firmware that opens `siot` through the secure NVS API**
   (`nvs_flash_secure_init_partition`) rather than the plain one the Arduino `Preferences`
   class uses. Both the provisioning listener and the device library need this, and they
   must agree, or the library opens a partition the listener wrote with different keys.

Until both land (roadmap 9.5, the unticked firmware item), the steps below protect the
firmware and the boot chain and **not** the credentials. Do not burn fuses on that basis
believing the secret is covered.

## The three mechanisms

| | Protects | Irreversible part | Cost to you |
|---|---|---|---|
| Flash encryption | Flash contents read off the chip, except NVS | Key and enable count in eFuse | Every later flash must be encrypted; release mode ends USB flashing entirely |
| NVS encryption | `siot` and any other NVS partition | Nothing in eFuse by itself; it rides on flash encryption | A partition-table and firmware change (above) |
| Secure Boot v2 | Running firmware you did not sign | Public-key digest in eFuse | Lose the signing key and the board never takes an update again |

Secure Boot v2 needs ESP32 silicon revision v3.0 or later. Older chips only support the
older Secure Boot v1. Check yours with `espefuse.py summary` before planning anything.

## You cannot do this from the Arduino IDE

Flash encryption and secure boot are enabled in the **bootloader**, which reads build-time
configuration (`CONFIG_SECURE_FLASH_ENC_ENABLED`, `CONFIG_SECURE_BOOT`, `CONFIG_NVS_ENCRYPTION`
and their mode settings). The Arduino core ships a prebuilt bootloader without them. To use
any of this, build the sketch with ESP-IDF, with the Arduino core as an ESP-IDF component,
and set the options in `menuconfig`. The SIoT library compiles against nothing outside the
ESP32 core, so it comes along unchanged.

## Development mode first, always

Flash encryption has two modes, and the difference is the whole decision.

**Development mode** leaves the serial bootloader able to write *encrypted* images
(`idf.py encrypted-flash`, or `esptool.py --encrypt`). It also lets you switch encryption off
again, a small fixed number of times, because the enable state is a counter of burned bits
(`FLASH_CRYPT_CNT`) and each switch burns one more. When they run out, the state is final.
A development-mode board is **not secure**: whoever can flash it can flash a firmware that
reads the flash back decrypted. Its value is that you find your mistakes while you can
still recover from them.

**Release mode** burns the fuses that stop the serial bootloader from encrypting, decrypting
or caching flash, write-protects the counter, and disables JTAG. After that, the only way to
change the firmware is over the air from firmware already running on the board, and SIoT's
library has no OTA path.

## What release mode does to SIoT's own flow

SIoT provisions by flashing a separate sketch (`firmware/esp32-provisioning`), writing the
credentials over Web Serial, then flashing the application on top (design 5.3,
`firmware/SIoT/README.md`). Every one of those flashes is a serial flash. So, on a
release-mode board:

- **Provisioning has to be finished before release mode is burned**, with the application
  already flashed on top, because neither can be flashed afterwards.
- **Rotating the secret (8.4) and `SIOT ERASE` (4.9) stop working**, since both need the
  listener sketch back on the board. Revoking a grant on such a device means retiring the
  device, not rotating it.
- **The sketch can never be changed again** without an OTA path you build yourself.

Development mode keeps all three working, at the price of not being secure against someone
who can reach the USB port. For most SIoT deployments the honest choice is either release
mode on a board that will never be touched again, or no hardening at all.

## Do not harden a board that is already provisioned

Turning NVS encryption on makes the existing plaintext `siot` partition unreadable, so the
board looks blank. The tempting fix is to write the same `DEVICE_ID` and `DEVICE_SECRET`
back from the vault. **Do not.** `boot_epoch` lived in that partition too, so the device
would start again at epoch 1 and reuse every nonce it has already used under the same key
(design 7.1). The server would refuse the repeated `seq` values, but it would still have
received the ciphertexts, and two ciphertexts under one key and nonce leak their plaintexts.

Harden the board first, then provision it. A board that is already in service is
provisioned again as a **new device**, with a new `DEVICE_ID` and `DEVICE_SECRET`. Its old
entry can stay in the vault so its history remains readable.

## Order of operations

On a spare board of the same revision first, every time.

1. `espefuse.py summary`. Note the silicon revision and confirm no security fuses are burned.
2. Build the listener and the application with ESP-IDF (Arduino as a component), the
   partition table with `nvs_keys`, and NVS encryption on. **This needs the firmware item
   above; until then, stop here.**
3. Enable flash encryption in **development** mode. Flash, let the first boot encrypt the
   flash in place (it takes a while; do not cut power), then provision from the web client
   and confirm the device uploads and its readings open.
4. If you are using secure boot: generate the signing key offline, back it up in two places,
   enable Secure Boot v2, and confirm a signed image boots and an unsigned one is refused.
5. Only when all of that has worked on this exact build: re-flash in release mode, or burn
   the release fuses with `espefuse.py`, knowing everything in "What release mode does"
   above now applies.

Throughout, keep in mind that `espefuse.py` asks for confirmation before each burn, and the
confirmation is the last moment a mistake is free.
