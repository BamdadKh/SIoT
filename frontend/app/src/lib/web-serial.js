/**
 * The Web Serial transport under the provisioning protocol (roadmap 4.5).
 *
 * `provisioning-protocol.js` decides what to say; this decides how to get it
 * down a wire and back. Split that way because the protocol is worth testing and
 * this is not testable at all: `navigator.serial` has no shim worth trusting, so
 * everything here was verified against a board instead.
 *
 * Chromium only, and that is design 5.3's deliberate narrowing rather than a gap.
 * The check below exists so the app can say so and point at the escape hatch,
 * never so it can quietly fall back to a path that puts the secret in a clipboard.
 */

import {
  eraseCommand,
  helloCommand,
  readIdCommand,
  writeCommand,
  parseResponse,
  isSupportedBanner,
  storedIdFrom,
  describeError,
} from './provisioning-protocol.js';

/** Matches `Serial.begin(115200)` in the sketch. Both sides or neither. */
const BAUD_RATE = 115200;

/** One command, one line back. A board that has not answered by now will not. */
const REPLY_TIMEOUT_MS = 4000;

/**
 * Most ESP32 dev boards wire DTR/RTS to the auto-reset circuit, so opening the
 * port reboots the board and the first second of the line is ROM chatter. Rather
 * than sleep a fixed amount and hope, the handshake is retried across this
 * window: a board that is already up answers immediately and a booting one
 * answers when it is ready.
 */
const HANDSHAKE_TIMEOUT_MS = 6000;
const HANDSHAKE_RETRY_MS = 500;

/** How often `#readLine` looks at the buffer the pump is filling. */
const POLL_MS = 15;

export function isWebSerialSupported() {
  return typeof navigator !== 'undefined' && 'serial' in navigator;
}

/**
 * Opens the browser's port chooser.
 *
 * Deliberately not filtered by USB vendor id. The filter would have to enumerate
 * every USB-serial bridge an ESP32 board might carry (CP2102, CH340, FTDI, the
 * ESP32-S series' native USB), and a board missing from that list looks broken
 * rather than unlisted. The `HELLO` handshake is the real check, and it tests
 * the thing that actually matters: whether the provisioning sketch is running.
 *
 * @returns {Promise<SerialPort>}
 * @throws if the user dismisses the chooser without picking anything.
 */
export function requestPort() {
  if (!isWebSerialSupported()) {
    throw new Error('this browser has no Web Serial support');
  }
  return navigator.serial.requestPort();
}

/**
 * A connection to a board running the provisioning sketch.
 *
 * Always `close()` it, including on the error paths: an open port stays open for
 * the life of the tab, and a second attempt then fails on a port already in use
 * with nothing on screen explaining why.
 */
export class ProvisioningSession {
  #port;
  #reader = null;
  #writer = null;
  #buffer = '';
  #ended = false;

  constructor(port) {
    this.#port = port;
  }

  /**
   * Opens the port and confirms the far end is the provisioning sketch.
   *
   * @throws if the port will not open, or if whatever answered is not a listener
   *         this client can drive.
   */
  async open() {
    await this.#port.open({ baudRate: BAUD_RATE });

    const decoder = new TextDecoderStream();
    this.#port.readable.pipeTo(decoder.writable).catch(() => {
      // Rejects when the port closes or the cable is pulled. The pump below
      // notices the same thing and has the context to report it.
    });
    this.#reader = decoder.readable.getReader();
    this.#writer = this.#port.writable.getWriter();
    this.#pump();

    const deadline = Date.now() + HANDSHAKE_TIMEOUT_MS;
    for (;;) {
      try {
        const response = await this.#exchange(helloCommand(), HANDSHAKE_RETRY_MS);
        if (isSupportedBanner(response)) return;
        throw new Error(
          'That port answered, but not with a provisioning sketch this page understands. Flash firmware/esp32-provisioning to the board first.',
        );
      } catch (failure) {
        if (failure?.name !== 'TimeoutError') throw failure;
        if (Date.now() >= deadline) {
          throw new Error(
            'The board did not answer. Check it is running the provisioning sketch from firmware/esp32-provisioning, and that no serial monitor has the port open.',
          );
        }
      }
    }
  }

  /**
   * @returns {Promise<string|null>} the stored `DEVICE_ID`, null if blank.
   */
  async readId() {
    return storedIdFrom(await this.#exchange(readIdCommand()));
  }

  /**
   * @param {string|null} expectedId what `readId` returned; the board re-checks it.
   * @param {string} deviceId base64url
   * @param {string} deviceSecret base64url
   */
  async write(expectedId, deviceId, deviceSecret) {
    const response = await this.#exchange(writeCommand(expectedId, deviceId, deviceSecret));
    if (!response.ok) throw new Error(describeError(response));
  }

  /**
   * Clears both credentials, for a board being retired rather than reused
   * (roadmap 4.9).
   *
   * @param {string} expectedId what `readId` returned; the board re-checks it.
   */
  async erase(expectedId) {
    const response = await this.#exchange(eraseCommand(expectedId));
    if (!response.ok) throw new Error(describeError(response));
  }

  async close() {
    // Cancel before release: a reader parked on a board that is saying nothing
    // holds the stream lock, and releasing it under that read throws. The cancel
    // also propagates up the pipe and unlocks `port.readable`, which `port.close`
    // requires.
    try {
      await this.#reader?.cancel();
    } catch {
      // Already gone. Nothing to recover, and closing must not fail on it.
    }
    try {
      await this.#writer?.close();
    } catch {
      // Same.
    }
    this.#reader = null;
    this.#writer = null;
    try {
      await this.#port.close();
    } catch {
      // A port whose cable was pulled is already closed.
    }
  }

  /**
   * One long-lived read loop rather than a read per command.
   *
   * The obvious shape here is to race `reader.read()` against a timeout inside
   * each exchange, and it is quietly wrong: when the timeout wins, the read is
   * still outstanding and will consume the next chunk off the wire and drop it
   * on the floor. That turns the handshake's retry loop into a way to lose the
   * board's answer rather than a way to wait for it. A single pump owns every
   * read, and callers wait on the buffer it fills.
   */
  #pump() {
    (async () => {
      try {
        for (;;) {
          const { value, done } = await this.#reader.read();
          if (done) break;
          this.#buffer += value;
        }
      } catch {
        // Cancelled by close(), or the cable went. Either way there is no more
        // to read, which is what #ended says.
      } finally {
        this.#ended = true;
      }
    })();
  }

  /**
   * Sends one line and returns the first response addressed to us.
   *
   * Lines that are not ours are dropped rather than counted: the boot banner and
   * ROM chatter arrive unpredictably, and a "first line back" rule would resolve
   * a command with whatever noise happened to be in flight.
   */
  async #exchange(command, timeoutMs = REPLY_TIMEOUT_MS) {
    // Anything already buffered predates this command and cannot be its answer.
    this.#buffer = '';
    await this.#writer.write(new TextEncoder().encode(`${command}\n`));

    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const line = await this.#readLine(deadline);
      const response = parseResponse(line);
      if (response !== null) return response;
    }
  }

  async #readLine(deadline) {
    for (;;) {
      const newline = this.#buffer.indexOf('\n');
      if (newline !== -1) {
        const line = this.#buffer.slice(0, newline);
        this.#buffer = this.#buffer.slice(newline + 1);
        return line;
      }
      // Checked after the buffer, not before: the last line can arrive in the
      // same chunk that ends the stream.
      if (this.#ended) throw new Error('The board disconnected.');
      if (Date.now() >= deadline) throw timeoutError();
      await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    }
  }
}

/**
 * A timeout during the handshake means "not up yet, retry"; anywhere else it
 * means the board stopped answering. Same condition, different meaning, so it
 * needs to be distinguishable from a real failure rather than a bare Error.
 */
function timeoutError() {
  const error = new Error('The board did not answer in time.');
  error.name = 'TimeoutError';
  return error;
}
