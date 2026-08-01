# SIoT Design Document

*"The S in IoT stands for security"*

Status: Architecture phase. A throwaway spike exists (unencrypted HTTP button counter) to validate the ESP32 → server path; none of the design below is implemented yet.
Last updated: July 31, 2026

---

## 1. Vision & Core Principle

SIoT is a zero-knowledge IoT security platform. The server is **fully untrusted by design** and functions purely as a dumb encrypted storage layer. At no point does it have access to plaintext device secrets, user data, or decryption keys.

This is treated as a non-negotiable constraint. Every architectural decision is evaluated against one question: does this give the server plaintext access to anything, even indirectly?

One clarification on what "untrusted" can and cannot buy us. Cryptography can stop the server from **reading** or **silently altering** anything. It cannot stop the server from **withholding** data by refusing to serve it, stalling, or deleting records. The guarantee this design targets is precise:

> **The server can withhold, but it cannot lie undetected.**

Availability is therefore an accepted residual risk (Section 13), not something the design pretends to solve.

---

## 2. Cryptographic Core

### 2.1 Key hierarchy

The user memorizes exactly one thing: their password. Everything below is derived or wrapped automatically, so key handling can be as conservative as we like without adding user burden.

```
password + salt
  └─ Argon2id(m=64 MiB, t=3, p=1) ──> master_key (32B)   [never leaves the device]
       ├─ HKDF-SHA256(info="siot/auth/v1")  ──> login_key (32B)   ──> sent to server
       └─ HKDF-SHA256(info="siot/kek/v1")   ──> kek (32B)         [key-encryption key]

vault_key (random 32B, generated once at signup)
  └─ AES-256-GCM-wrapped by kek ──> wrapped_vault_key   [stored server-side, opaque]

vault_key ──encrypts──> vault records (device secrets, schemas, grants, layout)
```

- The password never leaves the device.
- `login_key` is password-*equivalent* but not password-*revealing*: it authenticates, and it cannot be used to derive `kek`, because HKDF with distinct `info` labels makes the two outputs computationally independent.
- Salt is 128-bit, CSPRNG, unique per user, stored plaintext server-side. Safe because the password itself never travels.

### 2.2 Why the wrapped `vault_key` indirection

The vault is encrypted under a random `vault_key`, not directly under the password-derived key. This costs nothing in user experience and buys two things:

- **Password change re-wraps 32 bytes.** Derive the new `kek`, re-wrap `vault_key`, upload. Vault contents are never touched, never re-uploaded, and never briefly decrypted in bulk.
- **A future recovery path has a clean slot to hook into** — any second wrapping of the same `vault_key` (see Section 12) is an additive change, not a redesign.

Device keys are unaffected by password changes, since they live inside the vault rather than being derived from it.

### 2.3 Symmetric primitives

- **AEAD: AES-256-GCM** everywhere. Chosen because it is the only authenticated cipher available in both Web Crypto and ESP32 hardware acceleration. XChaCha20-Poly1305 would be a better fit for random nonces but has no Web Crypto support, and shipping a JS implementation to handle the user's keys is a worse trade than managing nonces carefully.
- **Nonces are never random on the device.** GCM nonce reuse under a fixed key is catastrophic because it leaks the authentication key, not just the plaintext. An ESP32 immediately after boot is a bad place to trust an RNG. The counter construction in Section 7.2 makes reuse structurally impossible instead of probabilistically unlikely.
- **All ciphertext binds its context as AAD.** Every record commits to who it belongs to, which device produced it, what kind of record it is, and where it sits in sequence. Without this the server cannot forge a record, but it can move a valid one into a different slot: swap a device's readings into another device's history or replay an old vault record into a newer field. AAD binding closes that hole.

---

## 3. Authentication & Sessions

- Client submits `login_key` to the server over TLS.
- **The server does not store `login_key`. It stores `Argon2id(login_key, server_salt)`** and compares in constant time.

That second server-side hash matters because without it a database dump is not just a pile of sealed vaults but a working login credential for every account. The vault would stay sealed either way, but the attacker would be authenticated and able to read metadata, delete records, or register devices. The client-side KDF protects the vault while the server-side KDF protects authentication. They defend different things and you need both.

- On match, the server creates a **server-side session** in Redis and returns a session identifier.
  - Session IDs are 256-bit CSPRNG stored hashed in Redis so a Redis dump won't hand over live sessions. They have an absolute TTL and an idle timeout.
  - Delivered as a cookie with `HttpOnly; Secure; SameSite=Strict`.
- Revocation is cheap and immediate because logout, logout-everywhere, or suspected compromise just deletes the corresponding Redis entry or all entries tied to a user. No blocklist workaround is needed, unlike with stateless tokens.
- **Login is rate-limited** per account and per source address, with exponential backoff. Zero-knowledge architecture does nothing to slow down online password guessing; that has to be enforced server-side.
- **Salt lookup must not leak account existence.** The salt is fetched by username before authentication, so an unknown username has to return something. Return a deterministic decoy using `HMAC(server_secret, username)` so the response is indistinguishable from a real account's and stable across retries.

No zero-knowledge proof is required at the login step itself. A standard hash comparison plus session issuance is sufficient because the password never transmits and the server never learns `kek`.

> **Considered and deferred:** an aPAKE (OPAQUE or SRP) would mean the server never receives a password-equivalent at all, even momentarily. It is the better primitive. It is also unavailable in Web Crypto, so adopting it means shipping unaudited JS crypto on the authentication path to defend against a threat that TLS plus server-side hashing already covers. Revisit for v2 if a well-audited browser implementation lands.

---

## 4. Transport Security

Zero-knowledge does not make the wire safe, and TLS was missing from earlier revisions of this document. It is mandatory:

- **HTTPS everywhere, TLS 1.3, HSTS with preload.** Plain HTTP is disallowed, including on the local network because "it's just my LAN" is exactly how the device-registration attack below succeeds.
- Three things break without it, none of which the crypto core protects:
  - `login_key` is password-equivalent in transit.
  - Session IDs are bearer tokens.
  - **Device public-key registration needs integrity at write time.** An active attacker who can rewrite that request substitutes their own public key and can then forge readings for the device forever. Confidentiality is irrelevant here because this is purely an integrity problem, and TLS is what solves it.
- **Devices pin the server's SPKI** (not the leaf certificate) in the library configuration.

> **Open item: certificate rotation.** Pinned firmware plus an expiring certificate is a fleet-bricking event, and devices may be physically inaccessible. Pinning the SPKI rather than the certificate means routine renewals are safe as long as the key pair is reused, but a key rotation still requires a plan. Options: pin a long-lived intermediate, ship a backup pin alongside the primary, or accept reflashing every affected board by hand. Not yet decided (Section 15).

---

## 5. Device Identity & Onboarding

Auto-provisioning (an earlier server-assisted handshake mode) has been **removed entirely**. It allowed the server to establish separate shared secrets with both the browser and the device in a DH-style relay, which is a textbook permanent man-in-the-middle position. Rather than patch it, the cleanest fix was to eliminate the mode outright.

**All pairing happens in the browser. The credentials never touch the server, and how they reach the board is the user's choice.**

### 5.1 Device key material

```
DEVICE_SECRET (random 32B, browser CSPRNG)
  ├─ HKDF-SHA256(info="siot/device/data/v1") ──> device_data_key (32B, AES-256-GCM)
  └─ HKDF-SHA256(info="siot/device/sign/v1") ──> ed25519_seed (32B) ──> device_sign_priv / device_sign_pub
```

The split is what makes read-only grants possible (Section 9). `device_data_key` is shareable and confers **read** access while `device_sign_priv` never leaves the device and confers **write** authority. A single symmetric key could not separate the two.

### 5.2 What the server learns

| Value | Visibility | Purpose |
|---|---|---|
| `DEVICE_ID` (128-bit random) | **Plaintext** | Lookup index; uniqueness enforced at registration |
| `device_sign_pub` | **Plaintext** | Verifying upload signatures — it's a public key, publishing it leaks nothing |
| `DEVICE_SECRET` | Encrypted in vault | Everything else; server never sees it |
| Device name | Encrypted in vault | A label for the owner (5.5). Deliberately absent from the `devices` table — "bedroom motion sensor" next to upload timestamps is a labelled occupancy log |
| Upload timing, record sizes, `last_seq` | **Plaintext, unavoidably** | Inherent to storing and validating records; read back as liveness (5.6). Accepted leakage, see 13.1 |

`device_sign_pub` in plaintext is what lets an untrusted server authenticate device uploads without holding anything secret. This closes a gap in earlier revisions where nothing specified how the server distinguished a genuine upload from an attacker POSTing garbage to a known `DEVICE_ID`. Every obvious answer (like having the device present `DEVICE_SECRET`) handed the server the secret and collapsed the core guarantee.

`DEVICE_ID` is generated with 128 bits of entropy, so accidental collision is negligible; the server additionally enforces uniqueness as a hard constraint, which it can do trivially without seeing anything sensitive.

### 5.3 Provisioning flow

**The supported path is ESP32, and the browser drives it end to end:**

1. Browser generates `DEVICE_ID` and `DEVICE_SECRET` locally.
2. Browser derives `device_sign_pub` and registers `(DEVICE_ID, device_sign_pub)` with the server.
3. Browser encrypts `DEVICE_SECRET` under `vault_key`, together with the device's name (5.5), and uploads it to the vault.
4. Provisioning tool writes `DEVICE_ID` + `DEVICE_SECRET` into a **dedicated NVS partition** over Web Serial.

The server never sees the plaintext secret at any point.

Physical USB access is treated as an **intentional security property** and not a limitation because it makes remote provisioning attacks structurally impossible.

Step 4 is what the whole flow is designed around, and it is worth being clear about what it buys over simply telling the user two strings. The secret never enters the clipboard, never lands in a source file, and never reaches a version control system. It is decoupled from the firmware image, so reflashing preserves it by construction. And because the tool has a channel to the board, it can read back what is already there, which is the only way the check in 5.4 can exist at all. None of that is available to a flow that ends at a text field.

The cost is that this path is exactly as portable as its two dependencies: Web Serial is Chromium-only, and the NVS partition scheme is ESP32-specific. That is an accepted narrowing, not an oversight — **one hardware target, done properly, with a published protocol so other targets are possible rather than pre-built.** See 5.3.1 and 6.1.

#### 5.3.1 Reveal credentials (deliberate escape hatch)

An explicit **Reveal credentials** control on a device shows `DEVICE_ID` and `DEVICE_SECRET` as base64url, decrypted from the vault in the browser. It exists so that someone writing their own client for other hardware has something to provision it with — without it, the published protocol in Section 7 is an invitation with no key attached.

This is **not** the normal flow and must not be presented as an equal alternative to it:

- It is reached by an intentional action on a device that already exists, never offered as a step in setup.
- It reveals on demand and does not stay revealed.
- It states its costs at the moment of revealing, not in documentation the user will not read: the secret is now in the clipboard and wherever they put it next; there is no overwrite protection outside the Web Serial path (5.4); and how it is stored on the target hardware is now entirely their problem, including whether it survives a firmware update.

Everything below the credentials — key derivation, AEAD, signing, sequence handling — is identical to the supported path. A third-party client that consumes revealed credentials and conforms to Section 7 is indistinguishable to the server from the reference library, which is the point: the server has no notion of a blessed implementation and gains nothing from one.

### 5.4 Overwrite protection

Before writing, the tool reads back any `DEVICE_ID` already present in NVS:

- **No ID present** → blank board, provision normally.
- **ID matches the selected vault record** → re-provisioning the same device, proceed.
- **ID present but different** → refuse, and surface a clear warning. Overwriting would orphan the existing vault record — the device would keep reporting under an identity nothing in the vault can decrypt anymore, with no way to recover it.

This check requires a channel to the board and therefore does not extend to revealed credentials (5.3.1). Somebody provisioning their own hardware owns that failure mode, and the reveal flow should say so rather than let it be discovered when a device goes quiet.

### 5.5 Device names

Devices are named by their owner — "greenhouse", "front door" — because a list of 128-bit identifiers is unusable the moment there is more than one.

**The name lives in the vault, encrypted under `vault_key`, in the same record as `DEVICE_SECRET`.** It is never sent to the server and there is no `name` column in the `devices` table. This is not a stylistic preference: names are the most directly revealing thing a user will ever type into this system. "Bedroom motion sensor" alongside upload timestamps the server already holds turns accepted metadata leakage (Section 13.1) into an occupancy log with labels on it. A server-side name field would leak more about a household than the encrypted payloads it accompanies.

Consequences that follow and should not be treated as bugs:

- Renaming a device is a vault write and bumps `vault_version` like any other.
- A locked vault cannot show names. A signed-in but locked client can list `DEVICE_ID`s and liveness (5.6) and nothing else, which is the honest rendering of what it actually knows.
- Names are not unique and are not identifiers. `DEVICE_ID` is the key everywhere; the name is a label on top of it, and two devices called "sensor" are the user's problem rather than a constraint violation.

### 5.6 Liveness

The device list shows which devices are currently reporting. The signal is derived from records the server already holds, so it costs no new disclosure — the server has always seen upload timing (Section 13.1), and it is precisely that metadata being read back.

**Liveness is a lower bound, and that asymmetry is the useful part.** A device is shown as reporting because a *new, signature-valid record at a higher `seq`* has arrived. The server cannot manufacture one: it would need a signature it cannot produce (Section 7.4, check 1) at a sequence number it cannot reuse (check 2). So the server **cannot make a silent device look alive**.

What it can do is the reverse — withhold records and make a live device look dead. That is the availability limit stated in Section 8 and Section 13, showing up here in a concrete form. It is the safe direction for this failure to point: a false "offline" prompts someone to go and look at the device, while a false "online" would let a server quietly cover for one that has stopped.

Two things follow for the UI:

- **Show when it was last heard from, not just a dot.** "Last reported 4 minutes ago" is a claim the client can substantiate; "online" is a summary of it. Devices report on wildly different schedules and a fixed threshold will call a well-behaved hourly sensor dead.
- **"Offline" must never be phrased as a fact about the device.** The client knows it has not received a record. Whether that is a flat battery, a dropped WiFi link, or a server declining to serve is not something it can distinguish.

---

## 6. Firmware & the Device Library

**The provisioning tool does not build, compile, or flash application firmware.** Earlier revisions described the browser decrypting `DEVICE_SECRET`, embedding it into a new firmware build, and reflashing — which is not implementable, because a browser cannot compile C++.

The fix is to stop coupling credentials to firmware images at all:

- **Credentials live in NVS, firmware lives in the app partition.** They are written independently and at different times.
- **The user writes and compiles their own sketch** in Arduino IDE or PlatformIO, exactly as they normally would, including the SIoT library. There is no per-device firmware blob stored on the server, no decrypt-and-re-embed step, and nothing the browser has to compile.
- **The library reads `DEVICE_ID` and `DEVICE_SECRET` from NVS** and handles key derivation, AEAD, signing, sequence persistence, and upload internally. `SIoT.begin()` takes no credentials, because on the supported path there are none to pass — the device already has them. The owner defines readings and actions and never touches crypto.
- **Firmware updates preserve `DEVICE_SECRET` by construction** because reflashing the app partition leaves NVS untouched. There is no regeneration step, no decrypt-and-re-embed step, and no per-device firmware blob stored on the server.

### 6.1 Portability

**Scope is deliberately one hardware target with a published protocol, rather than several half-supported ones.** The ESP32 library is the reference implementation and the only one shipped. Section 7 is the specification anyone else builds against: KDF labels, AEAD parameters, nonce construction, AAD layout, payload shape, signature input, and the three server checks. Together with the API documentation for `POST /records` and the reveal flow in 5.3.1, that is everything a conforming client needs.

This works because **the server has no concept of a blessed implementation.** It verifies an Ed25519 signature, checks a sequence number, checks a nonce, and stores an opaque blob. A Raspberry Pi, an nRF, an STM32 or a Python script that produces conforming records is accepted on exactly the same terms as the reference library, with no server change and no registration of client type. There is nothing to whitelist because there is nothing being trusted.

What a port has to supply for itself, all of which the ESP32 library handles:

- **Credential storage.** Obtained through 5.3.1; where it lives afterwards is the porter's decision, and the overwrite protection of 5.4 does not extend to it.
- **A persisted `boot_epoch`** (Section 7.1). This is the one requirement that is not negotiable on any hardware — a client that forgets it repeats a `seq` and reuses a nonce, which is a break, not a bug.
- **A correct AES-256-GCM and Ed25519**, and the discipline to derive both device keys from `DEVICE_SECRET` with the exact HKDF labels rather than inventing equivalents.

### 6.2 Consequences worth stating plainly

- **User-authored firmware cannot be hash-verified.** Section 10's verification therefore covers the web client and official library releases only. The extension can tell you the library you pulled is the published one but cannot vouch for the sketch you wrote around it.
- **NVS is plaintext flash unless ESP32 flash encryption is fused.** Anyone with physical possession and a USB cable can read `DEVICE_SECRET` out. This sits inside the already-accepted physical-access risk, but deployments that care should burn the flash-encryption and secure-boot fuses. Document it as a recommended hardening step and note that it is irreversible.
- **Revealing credentials (5.3.1) moves the secret somewhere none of the above covers: the user's own machine.** It passes through the clipboard and comes to rest wherever they put it, where a synced editor, a backup, or a stray `git add` reaches it. Nothing in this document protects it after that point. This is the reason reveal is an escape hatch behind a deliberate action rather than a second supported path — the guarantee genuinely stops there, and a flow that made it look routine would be lying about where the boundary is.

---

## 7. Device Wire Protocol

This is the interoperability contract. Byte-level detail is deliberate — it is what makes third-party libraries possible.

### 7.1 Sequence numbers

Each device keeps two counters, one of which must survive a power cut:

- `boot_epoch` (uint32) — **persisted** to non-volatile storage (NVS on ESP32, whatever the port's equivalent is elsewhere), incremented once per boot before any record is produced.
- `msg_counter` (uint32) — RAM only, reset to zero each boot, incremented per record.

`boot_epoch` is the one piece of state a port cannot do without (Section 6.1). Storage medium is the porter's choice; forgetting it is not an option — a device that loses its `boot_epoch` repeats a `seq`, and repeating a `seq` under a counter-derived nonce is the nonce reuse that Section 7.2 exists to make impossible.

```
seq (uint64) = (boot_epoch << 32) | msg_counter
```

`seq` is strictly increasing across reboots and power loss without requiring an RTC, network time, or a trustworthy RNG at startup.

Readers verify **strict monotonicity, not contiguity**. A reboot advances the high word and zeroes the low word, producing a large legitimate jump. That jump is distinguishable from tampering because gaps within a single `boot_epoch` indicate dropped or withheld records, whereas a `boot_epoch` increment is a normal restart.

### 7.2 Nonce construction

```
nonce (12B) = 0x00000000 || seq (8B, big-endian)
```

Since `seq` is strictly increasing and `device_data_key` is fixed for the life of the secret, **nonce reuse cannot occur**. No RNG quality assumption, no birthday-bound budgeting, and no state to reconcile after an unclean shutdown is needed because the counter is persisted before use. The worst case after power loss is a skipped `seq`, never a repeated one.

### 7.3 Record format

```
plaintext P   = CBOR { t: <device timestamp>, r: <readings per declared schema> }
AAD           = version (1B) || DEVICE_ID (16B) || record_type (1B) || seq (8B)
ciphertext C  = AES-256-GCM(device_data_key, nonce, P, AAD)
signature S   = Ed25519(device_sign_priv, AAD || nonce || C)

POST /records
{ device_id, seq, nonce, ciphertext: C, sig: S }
```

The signature covers the AAD, the nonce, and the ciphertext — so sequence position, device identity, and record type are all authenticated, not just the payload.

### 7.4 Server-side validation

The server performs exactly three checks, none of which require decryption:

1. `Ed25519_verify(device_sign_pub, AAD || nonce || C, S)` — is this really from that device?
2. `seq > last_seq[device_id]` — is this fresh, not a replay?
3. `nonce == 0x00000000 || seq` — is the nonce well-formed and consistent with the claimed sequence?

Then it stores the blob and updates `last_seq`. It never decrypts, and it cannot produce a record that passes check 1.

---

## 8. Data Integrity & Freshness

Encryption alone does not stop an untrusted server from serving you *stale* or *incomplete* data. Every blob it returns can be perfectly authentic and the overall picture still be a lie — last week's vault, a history with the inconvenient readings removed. Three mechanisms, all cheap:

- **Monotonic `vault_version`.** Every vault write carries a version inside the AEAD-protected plaintext. The client caches the highest version it has seen (IndexedDB) and **refuses anything lower**, surfacing a warning rather than silently accepting. A rollback becomes a visible, loud failure.
- **Strictly increasing `seq` on device records** (Section 7.1). Withheld or reordered readings leave a detectable hole in the sequence.
- **AAD binding on everything** (Section 2.3). The server cannot relocate a valid blob into a different slot, swap records between devices, or replay an old vault record into a newer field.

What remains unfixable is that the server can refuse to serve, stall indefinitely, or delete. No cryptographic mechanism recovers data that is simply gone. This is the concrete meaning of *"can withhold, cannot lie undetected"* and the reason availability is listed as accepted residual risk rather than mitigated.

Device liveness (Section 5.6) is the same asymmetry made visible in the UI, and is worth noting here because it is the one place a user reads freshness directly. The server cannot fabricate a newer signed record at a higher `seq`, so it cannot make a dead device look alive; it can withhold and make a live one look dead. Every freshness signal in this system fails in that direction, and none of them should ever be phrased as certainty about the world rather than about what has been received.

---

## 9. Inter-Device Automations (Read-Only Key Grants)

- Client decrypts `device_B_data_key` from the vault, re-encrypts it under `device_A_data_key`, and uploads the result as a key grant:

```
grant = AES-256-GCM(device_A_data_key, nonce, device_B_data_key,
                    AAD = "grant/v1" || DEVICE_ID_A || DEVICE_ID_B)
```

- Device A fetches the grant, decrypts it locally, and can now read Device B's data autonomously.
- The server sees only encrypted blobs throughout the entire exchange.
- No always-on client is required — the system is fully peer-to-peer once the grant exists.

### 9.1 Grants are read-only

**Only `device_data_key` is shared. `device_sign_priv` never leaves Device B.**

This is why the key split in Section 5.1 exists. Under the earlier single-symmetric-key design, granting A the ability to read B necessarily also granted it the ability to write as B because anyone holding the key could encrypt convincing readings and attribute them to B. A compromised temperature sensor could have fabricated the smoke detector's output.

Now the capabilities are cleanly separated:

| Capability | Device B | Device A (granted) | Server |
|---|---|---|---|
| Decrypt B's records | ✓ | ✓ | ✗ |
| Verify B's signatures | ✓ | ✓ | ✓ (public key) |
| Produce records signed as B | ✓ | ✗ | ✗ |

A reader can always check authenticity, because `device_sign_pub` is public. A reader can never forge, because the private half stayed on the device.

### 9.2 Scope: historical as well as live

Once Device A holds `device_B_data_key`, it is not limited to a live feed from B because it can query the server for B's already-uploaded records and decrypt them locally. **A grant extends read access to everything B has stored, past and future.** That is a deliberate capability, but it should be presented to the user as such at grant time, not buried. This is not just "let A see what B is doing now."

### 9.3 Revocation is rotation

**Grants cannot be revoked for data already encrypted under the shared key** because A holds the key and that is irreversible. Revocation means rotating B's `DEVICE_SECRET`, which requires physically re-provisioning and reflashing the board (Section 5.3) and only protects data produced after the rotation. All of B's history remains readable by A forever.

This must be surfaced in the UI before a grant is created. A user who believes "revoke" means "A can no longer read B" will be wrong in a way that matters.

---

## 10. Client Verification System

A minimal, deliberately non-updating browser extension (~100 lines, open source) is the trust anchor for the code the user runs. **The extension is optional.**

- **On install:** no stored hash exists, so the extension forces code review, the user approves, and the hash is stored locally.
- **On update:** when a hash mismatch is detected, the extension fetches raw code from GitHub, computes its own hash (never trusting a claimed hash), shows a diff, and waits for user approval.
- Applies to site code, official library releases, and custom widget plugins (Section 11).

Being optional matters for the threat model because the core zero-knowledge guarantees hold with or without the extension since they are enforced by cryptography, not by the extension. What it adds is protection against a separate threat: a compromised server serving altered JavaScript to the browser, a standard web supply-chain attack. Without it, unverified web client code is part of the residual attack surface (Section 13).

### 10.1 Feasibility constraints

Two things need resolving before this ships, and neither is a detail:

- **Manifest V3 removed blocking `webRequest`.** An extension can no longer reliably intercept and block a script before the page executes it. Verification may therefore be after-the-fact: a warning once malicious code has already run, which is a materially weaker guarantee. Likely mitigation is to pair the extension with a strict CSP and Subresource Integrity so the browser enforces what the extension merely audits, and pin the SRI manifest rather than individual bundles.
- **"No auto-update" conflicts with the Chrome Web Store** because it updates extensions silently. Honoring the no-auto-update property requires self-hosting or unpacked developer-mode installation, both of which hurt adoption enough to affect whether anyone actually runs the extension.

A hash-pinning extension that verifies only the entry HTML while a hashed SPA bundle loads separately would be checking the wrong thing entirely. Whatever ships must cover every executed subresource.

---

## 11. Customizability & Dashboard

- Devices declare a **schema** at pairing time; the schema itself is encrypted into the vault.
- The client auto-renders the dashboard from this schema — no hardcoding per device type.
- Generic widget system: graph, gauge, toggle, with drag-and-drop layout.
- The firmware library handles all crypto and communication internally — the device owner just defines readings and actions.

### 11.1 Schemas are untrusted input

A schema drives UI rendering, and schemas can arrive from granted devices belonging to other users. Treat them as hostile input: **strict validation against an allowlist of field types, no raw HTML rendering, no `dangerouslySetInnerHTML`, no dynamic code paths.** A malicious schema must not be able to reach XSS — decrypting an attacker's blob and injecting it into the DOM would hand them the very keys the whole architecture exists to protect.

### 11.2 Widget plugins need a sandbox

Custom widget plugins are arbitrary third-party JavaScript running inside the client that holds decrypted keys. Hash-pinning tells you which code is running but does not constrain what that code can do once approved, and the extension is optional anyway.

Plugins must run in a sandboxed iframe or Worker and communicate only over `postMessage`. They must never receive key material or raw vault access. The host passes in already-decrypted display values and receives back rendering instructions. A plugin should be incapable of exfiltrating a key even if the user approved it while it was malicious.

---

## 12. Account Recovery — Open Question

**There is no account recovery in v1.** If you forget your password, the account and all its data are permanently lost.

This must be stated bluntly because it needs to be stated bluntly, in the UI as well as here.

The previously specified mechanism using five security questions, normalized and concatenated into a KDF producing a key that wraps `master_key`, has been removed. Two reasons exist, and the first is the serious one:

- **The recovery blob was an offline brute-force oracle.** It sits on the server and security answers carry far less entropy than a password. Anyone who dumped the database could grind the answer space offline and recover the vault key. That reduces every account's security to the minimum of password strength and answer strength, so the recovery path intended as a safety net would have quietly become the cheapest way in. Adding a recovery mechanism weaker than the primary credential does not add a fallback but rather replaces the primary credential from the attacker's point of view.
- **Concatenating all five answers made it all-or-nothing.** Forget one of five and recovery fails completely, which is a high lockout risk for something whose entire purpose is preventing lockout.

Dropping it is a net security improvement, not merely a deferral. The attack surface genuinely shrinks.

If recovery returns, the Section 2.2 indirection is where it attaches: any second wrapping of `vault_key` is additive. Directions worth evaluating, given the constraint that the user must not have to remember anything beyond their password:

- **Shamir k-of-n** over answers (e.g. 3-of-5), fixing the all-or-nothing failure but not the entropy problem.
- **A printed/downloaded recovery code** with real entropy — strong, but it is a physical artifact to store, not something memorized.
- **Social recovery** — shares distributed to trusted contacts' vaults.
- **Rate-limited server-assisted recovery**, which requires giving up some zero-knowledge property and should probably be rejected on those grounds.

Whatever is chosen, the recovery credential must be at least as strong as the password, or it becomes the weakest link by definition.

---

## 13. Threat Model / Attack Surface

| Residual risk | Why it remains |
|---|---|
| Weak passwords | User choice, outside the system's control; mitigated by Argon2id and login rate limiting |
| **Permanent lockout** | No recovery path in v1 because forgetting the password destroys the account (Section 12) |
| Social engineering | Includes a user approving a malicious update without reading the diff |
| Physical device access | Accepted tradeoff because the same USB requirement kills remote provisioning attacks. NVS is plaintext unless flash encryption is fused |
| **Revealed credentials** | Only if the user deliberately reveals them (5.3.1) to port to other hardware. `DEVICE_SECRET` leaves the vault into the clipboard and whatever they do next is outside this document's guarantees |
| Memory scraping | Only relevant if the device is already compromised |
| Unverified web client code | Only a risk if the browser extension is not installed, which is optional and not required for the core crypto guarantees |
| **Metadata leakage** | Inherent to the architecture and significant for IoT (see below) |
| **Availability and withholding** | The server can refuse, stall, or delete. Cryptography detects lies but cannot compel service |
| **Compromised device holding a grant** | Reads everything the grant covers, including full history; revocation requires physical re-provisioning (Section 9.3) |

### 13.1 Metadata leakage

The server cannot read content but sees the shape of everything: how many devices exist, when each one uploads, how large each record is, which devices hold grants on which others, and when a client fetches what. It does **not** see device names (Section 5.5), which is the difference between an unlabelled timing trace and one annotated with what each device is and where it sits.

**For IoT this is not a minor leak.** A motion sensor that uploads only on activity leaks occupancy patterns to a fully passive server without a single byte being decrypted. Upload timing alone can reveal when a house is empty. Encrypting the payload does not hide the fact that a payload existed at 3:47am.

Partial mitigations exist and none are free: fixed-interval uploads with padded dummy records, constant-size payloads, and batching with jitter. All trade power consumption and latency for privacy, and the tradeoff differs per device class. **Not addressed in v1** but it must be an explicit, documented limitation rather than an unnoticed one because users will reasonably assume "zero-knowledge" covers it.

---

Every purely software-level trust assumption in the server has been eliminated by design. The remaining risks are physical, human, or metadata, categories that cryptography does not reach.

---

## 14. Stack

| Layer | Choice |
|---|---|
| Frontend | React + Web Crypto API |
| Backend | Node.js + TypeScript + Fastify |
| Extension | Vanilla JS, ~100 lines, no build step, no auto-update, optional |
| Firmware | C++ library, Arduino-compatible; published protocol spec for third-party ports |
| Provisioning | Web Serial API (in-browser), writes NVS credentials only. Reveal-credentials escape hatch for third-party ports (5.3.1) |
| Transport | HTTPS / TLS 1.3, HSTS preload, SPKI pinning on devices |
| Password KDF | Argon2id (m=64 MiB, t=3, p=1) client-side; Argon2id again server-side on `login_key` |
| Key derivation | HKDF-SHA256 with domain-separated `info` labels |
| AEAD | AES-256-GCM with counter-derived nonces and AAD context binding |
| Device auth | Ed25519, public key registered plaintext server-side |
| Session | Server-side session store (Redis), hashed 256-bit IDs, TTL |
| Recovery | **None in v1** — open question (Section 12) |
| Database | PostgreSQL (users, salts, device public keys, encrypted blobs) + Redis (sessions) |
| Hardware target | ESP32 + assorted sensors |

*Fastify was chosen over Express for TypeScript-first design, a structured plugin system, and built-in JSON schema validation.*

---

## 15. Open Decisions

The architecture is settled in shape. These remain genuinely open and should be resolved before or during implementation:

1. **Certificate rotation strategy for pinned devices** (Section 4) — backup pins, intermediate pinning, or accepted re-provisioning.
2. **Extension enforcement under Manifest V3** (Section 10.1) — whether CSP + SRI can carry the guarantee that blocking `webRequest` no longer provides.
3. **Extension distribution** (Section 10.1) — self-hosted versus Web Store, trading the no-auto-update property against adoption.
4. **Account recovery** (Section 12) — whether any mechanism can meet the bar of being no weaker than the password.
5. **Metadata mitigation** (Section 13.1) — whether any device class warrants padded fixed-interval uploads in v1.
6. **Vault record granularity** — one blob versus per-record encryption, affecting sync cost and how precisely `vault_version` rollback can be detected.

---

## 16. Changes in This Revision

| Change | Section | Why |
|---|---|---|
| Device Ed25519 keypair; public key registered plaintext | 5 | Upload authentication was unspecified; every obvious alternative leaked `DEVICE_SECRET` to the server |
| `DEVICE_SECRET` split into data key + signing key | 5.1, 9.1 | Grants conveyed forgery capability; read and write are now separable |
| Provisioning writes NVS credentials only; no firmware building | 6 | The previous update flow required the browser to compile C++ |
| ESP32 + Web Serial kept as the one supported path; reveal added as an escape hatch | 5.3, 6.1 | Copy-paste was briefly made the default to widen hardware support, and it cost the properties the guided flow exists to provide: no clipboard exposure, no secret in source control, and the overwrite check of 5.4. One target done properly plus a published protocol serves ports better than a second half-supported path |
| Device names, encrypted in the vault | 5.5 | A list of 128-bit identifiers is unusable past one device; a server-side name field would turn accepted timing metadata into a labelled occupancy log |
| Device liveness derived from signed records | 5.6, 8 | Users need to know a device has stopped. The server cannot forge a newer signed record, so it can only make a device look *more* offline — the safe direction |
| Per-device encrypted firmware blob removed | 6 | Obsolete once credentials are decoupled from firmware images |
| Server stores `Argon2id(login_key)`, not `login_key` | 3 | A database dump was a working login credential for every account |
| Wrapped random `vault_key` introduced | 2.2 | Password change re-wraps 32 bytes; clean attachment point for future recovery |
| Transport security section added | 4 | TLS was absent from the document entirely |
| Data integrity & freshness section added | 8 | Encryption addressed confidentiality but not rollback, omission, or reordering |
| AAD context binding on all ciphertext | 2.3 | Server could relocate valid blobs between slots |
| Full wire protocol specified | 7 | Required for third-party library ports; also pins down GCM nonce safety |
| Security-question recovery removed | 12 | Offline brute-force oracle reducing accounts to `min(password, answers)` |
| Metadata leakage added to threat model | 13.1 | Upload timing leaks occupancy regardless of encryption |
| Availability added as accepted risk | 1, 13 | Clarifies the achievable guarantee: withhold yes, lie undetected no |
| Schema validation & plugin sandboxing | 11.1, 11.2 | Decrypted third-party content reached the DOM and key material |
| MV3 / Web Store feasibility flagged | 10.1 | Blocking interception and no-auto-update may not both be achievable |
| "No open decisions remaining" replaced | 15 | Six were outstanding |
