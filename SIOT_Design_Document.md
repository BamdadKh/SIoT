# SIOT — Design Document

*"The S in IoT stands for security"*

Status: Planning & architecture phase (implementation not yet started)
Last updated: July 31, 2026

---

## 1. Vision & Core Principle

SIOT is a zero-knowledge IoT security platform. The server is **fully untrusted by design** — it functions purely as a dumb encrypted storage layer. At no point does it have access to plaintext device secrets, user data, or decryption keys.

This is treated as a non-negotiable constraint: every architectural decision is evaluated against a single question — *does this give the server plaintext access to anything, even indirectly?*

---

## 2. Cryptographic Core

- User's password never leaves the device.
- `KDF(password + salt) → master_key` (local, client-side).
- `master_key` splits into two derived values:
  - `login_hash` — sent to the server, used only for authentication.
  - `encryption_key` — never leaves the device, used to decrypt the vault.
- Salt is stored in plaintext server-side. This is safe because the password itself never travels over the network.
- Per-device keys are stored **encrypted inside the vault**, keyed by `encryption_key`.
- All IoT data is encrypted by the device itself before it ever reaches the server.
- Password changes only re-encrypt the vault; individual device keys are untouched.

---

## 3. Authentication & Sessions

- Client submits `login_hash` to the server; server compares against the stored hash.
- On match, server creates a **server-side session**, stored in Redis, and returns a session identifier to the client.
- Revocation is cheap and immediate this way — logout, logout-everywhere, or suspected compromise just means deleting the corresponding Redis entry (or all entries tied to a user). No blocklist workaround needed, unlike with stateless tokens.
- No zero-knowledge proof is required at the login step itself — it's a standard hash-comparison + session issuance, which is sufficient because the password never transmits and the server never learns the encryption key.

---

## 4. Device Onboarding & Flashing

Auto-provisioning (an earlier server-assisted handshake mode) has been **removed entirely**. It allowed the server to establish separate shared secrets with both the browser and the device in a DH-style relay, which is a textbook permanent man-in-the-middle position. Rather than patch it, the cleanest fix was to eliminate the mode outright.

**All pairing now happens through one path: a browser-based flashing tool using the Web Serial API.**

- The browser generates `DEVICE_ID` and `DEVICE_SECRET` locally, with enough randomness (e.g. 128-bit) that accidental ID collision between devices is negligible.
- The server additionally enforces `DEVICE_ID` uniqueness as a hard constraint at registration time — `DEVICE_ID` is stored in plaintext as the server's lookup index (only `DEVICE_SECRET` is encrypted), so this check is trivial for the server to perform without seeing anything sensitive.
- Both `DEVICE_ID` and `DEVICE_SECRET` are embedded directly into the firmware before it's flashed over USB.
- `DEVICE_SECRET` is encrypted with `master_key` and uploaded to the vault.
- The server never sees the plaintext secret at any point.
- Physical USB access to the device is treated as an **intentional security property**, not a limitation — it's what makes remote provisioning attacks structurally impossible.

---

## 5. Firmware Updates

- `DEVICE_SECRET` is **preserved** across updates — there is no regeneration step.
- Update flow: browser decrypts the existing secret from the vault → embeds it into the new firmware build → reflashes over USB.
- An **encrypted firmware blob is stored per device** on the server, enabling the browser extension (Section 8) to independently hash and verify the integrity of what was actually flashed against what's claimed.

**Device identity verification before reflash.** Because an update embeds a specific device's stored `DEVICE_ID`/`DEVICE_SECRET` into whatever board is currently plugged in, picking the wrong vault record (or having the wrong physical board connected) would silently create two devices sharing the same identity and secret. To prevent that:

- On connect, the flashing tool reads back the `DEVICE_ID` already stored on the connected board (from a fixed flash memory address) over Web Serial.
- This read-back ID is compared against the `DEVICE_ID` of the vault record the user selected for the update.
- If they don't match, the tool refuses to proceed and surfaces a clear warning — e.g. "connected device doesn't match the selected record" — instead of silently reflashing.

---

## 6. Account Recovery (Security Questions)

Recovery is handled entirely through **user-chosen security questions** — no email verification, no external proof system.

- User sets up a minimum of **5 security question/answer pairs** during account setup.
- Each answer is normalized before use: **lowercased, spaces and special characters stripped**. This means formatting quirks (capitalization, punctuation, trailing whitespace) can't cause recovery to fail on an otherwise-correct answer, without meaningfully reducing the entropy that matters.
- Normalized answers are concatenated, then fed into a local `KDF(answers) → recovery_key`. Normalization and hashing both happen client-side — the server never sees the answers, normalized or not.
- `recovery_key` derives a `recovery_master_key`.
- `recovery_master_key` encrypts `master_key` into a blob stored server-side. The server cannot decrypt this blob — it's opaque ciphertext, same as everything else in the vault.
- **Recovery flow:** user re-enters their answers → client normalizes and concatenates them → re-derives `recovery_key` → `recovery_master_key` → decrypts the stored blob → recovers `master_key` locally.

**Design consideration:** since this is the *only* recovery path, the security-answer set should be treated with the same rigor as the primary password — the 5-question minimum and normalization step both help, but predictable/public-record questions (schools attended, pet names, etc.) are still worth avoiding in favor of ones only the user would plausibly know. This overlaps with "social engineering," already listed as an accepted residual risk in Section 10.

---

## 7. Inter-Device Automations (Peer-to-Peer Key Grants)

- Client decrypts `device_B_key` from the vault, re-encrypts it with `device_A_key`, and uploads the result as a "key grant."
- Device A fetches the grant, decrypts it locally, and can now read Device B's data autonomously.
- The server sees only encrypted blobs throughout the entire exchange.
- No always-on client is required — the system is fully peer-to-peer once the grant exists.
- **Querying via the server, not just live relay:** once Device A holds a decrypted copy of `device_B_key`, it isn't limited to a live/real-time feed from Device B directly — it can query the server for Device B's already-uploaded encrypted data (past readings included) and decrypt them locally. The grant effectively extends read access to everything Device B has stored, both historical and future, not just whatever's happening in real time.

---

## 8. Client Verification System

A minimal, deliberately non-updating browser extension (~100 lines, open source) is the trust anchor for everything the user is asked to approve. **The extension is optional.**

- **On install:** no stored hash exists → forced code review → user approves → hash stored locally.
- **On update:** hash mismatch detected → extension fetches raw code from GitHub → computes its own hash (never trusts a claimed hash) → shows a diff → user approves.
- The same flow applies uniformly to site code, firmware, and custom widget plugins (Section 9).

Being optional matters for the threat model: the core zero-knowledge guarantees (server never sees plaintext) hold with or without the extension, since those are enforced by the cryptography itself, not by the extension. What the extension adds is protection against a *separate* threat — a compromised or malicious server serving altered JavaScript to the browser (a standard web supply-chain attack). Without it installed, unverified web client code becomes part of the residual attack surface (see Section 10); with it, the user has an independent, non-updating check on exactly what code they're running.

---

## 9. Customizability & Dashboard

- Devices declare a **schema** at pairing time; the schema itself is encrypted into the vault.
- The client auto-renders the dashboard from this schema — no hardcoding required per device type.
- Generic widget system: graph, gauge, toggle, with drag-and-drop layout.
- Custom widget plugins go through the same extension-based hash-pinning verification as site code and firmware, when the extension is installed.
- The firmware library handles all crypto and communication internally — the end user (device owner) just defines readings and actions.

---

## 10. Threat Model / Attack Surface

| Residual risk | Why it remains |
|---|---|
| Weak passwords | Password strength is a user choice outside the system's control |
| Weak/guessable security answers | Sole recovery factor — same category of risk as weak passwords, see Section 6 |
| Social engineering | Includes a user approving a malicious update without reading the diff, or someone extracting security-question answers |
| Physical device access | Accepted tradeoff — the same USB requirement that kills remote provisioning attacks |
| Memory scraping | Only relevant if the device is already compromised |
| Unverified web client code | Only a risk if the browser extension (Section 8) isn't installed — it's optional, not required for the core crypto guarantees |

Every purely *software-level* trust assumption in the server has been eliminated by design.

---

## 11. Stack

| Layer | Choice |
|---|---|
| Frontend | React + Web Crypto API |
| Backend | Node.js + TypeScript + Fastify |
| Extension | Vanilla JS, ~100 lines, no build step, no auto-update, optional |
| Firmware | C++ library, Arduino-compatible |
| Flashing | Web Serial API (in-browser) |
| Auth | Two-layer KDF → login_hash / encryption_key split |
| Session | Server-side session store (Redis) |
| Recovery | 5+ security questions → normalized → local KDF → recovery_key (no server-side answer verification) |
| Database | PostgreSQL (users/salts) + Redis (sessions) |
| Hardware target | ESP32 + assorted sensors |

*Fastify was chosen over Express for TypeScript-first design, a structured plugin system, and built-in JSON schema validation.*

---

## 12. Status

Architecture is considered locked for v1 implementation — no open decisions remaining at this stage.
