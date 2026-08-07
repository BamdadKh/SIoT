// Roadmap 4.5: the serial protocol the browser speaks to the provisioning sketch.
//
// The other end is firmware/esp32-provisioning/esp32-provisioning.ino. These
// cases and the 18-case hardware probe that verified the sketch check the same
// protocol from opposite sides; the strings below are the ones a real board
// actually sent and accepted over COM6, not invented shapes.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  helloCommand,
  readIdCommand,
  writeCommand,
  eraseCommand,
  parseResponse,
  isSupportedBanner,
  storedIdFrom,
  classifyBoard,
  describeError,
  PROTOCOL_BANNER,
  NO_ID,
  BLANK,
  SAME,
  OCCUPIED,
} from '../app/src/lib/provisioning-protocol.js';

const ID_A = 'AAECAwQFBgcICQoLDA0ODw';
const ID_B = 'EBESExQVFhcYGRobHB0eHw';
const SECRET = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

/* --- commands ------------------------------------------------------------ */

test('the fixed commands are exactly what the sketch matches on', () => {
  assert.equal(helloCommand(), 'SIOT HELLO');
  assert.equal(readIdCommand(), 'SIOT READ-ID');
});

test('a write to a blank board sends - as the expected id', () => {
  // The sketch compares this against what it finds, so `-` is a claim that the
  // board is blank rather than a placeholder meaning "no opinion".
  assert.equal(writeCommand(null, ID_A, SECRET), `SIOT WRITE ${NO_ID} ${ID_A} ${SECRET}`);
});

test('a write to an occupied board carries the id that was read', () => {
  assert.equal(writeCommand(ID_A, ID_B, SECRET), `SIOT WRITE ${ID_A} ${ID_B} ${SECRET}`);
});

test('a write with nothing to write is refused before it reaches the wire', () => {
  assert.throws(() => writeCommand(null, '', SECRET), TypeError);
  assert.throws(() => writeCommand(null, ID_A, ''), TypeError);
});

test('an erase carries the id the board is expected to be holding', () => {
  assert.equal(eraseCommand(ID_A), `SIOT ERASE ${ID_A}`);
});

test('an erase with no expectation is refused before it reaches the wire', () => {
  // There is deliberately no "erase whatever is there" form. A wildcard erase is
  // a command that wipes whichever board happens to be plugged in, which is the
  // shape the compare-and-swap exists to refuse.
  assert.throws(() => eraseCommand(null), TypeError);
  assert.throws(() => eraseCommand(''), TypeError);
  assert.throws(() => eraseCommand(NO_ID), TypeError);
});

/* --- responses ----------------------------------------------------------- */

test('an OK with no value parses as a bare success', () => {
  assert.deepEqual(parseResponse('SIOT OK'), { ok: true, value: null });
});

test('an OK carries its value', () => {
  assert.deepEqual(parseResponse(`SIOT OK ${ID_A}`), { ok: true, value: ID_A });
});

test('an error splits into a code and the rest', () => {
  assert.deepEqual(parseResponse(`SIOT ERR STALE ${ID_A}`), {
    ok: false,
    code: 'STALE',
    detail: ID_A,
  });
  assert.deepEqual(parseResponse('SIOT ERR TOO-LONG'), {
    ok: false,
    code: 'TOO-LONG',
    detail: null,
  });
  assert.deepEqual(parseResponse('SIOT ERR BAD-LENGTH device_id must be 16 bytes of base64url'), {
    ok: false,
    code: 'BAD-LENGTH',
    detail: 'device_id must be 16 bytes of base64url',
  });
});

test('a trailing carriage return is tolerated', () => {
  // The sketch uses Serial.println, which sends \r\n.
  assert.deepEqual(parseResponse('SIOT OK\r'), { ok: true, value: null });
  assert.deepEqual(parseResponse(`SIOT OK ${ID_A}\r`), { ok: true, value: ID_A });
});

test('anything not addressed to us is noise, not an error', () => {
  // The port carries ROM bootloader chatter, and whatever a serial monitor left
  // behind. Treating any of it as a malformed response would resolve a command
  // with something that was never an answer.
  assert.equal(parseResponse('rst:0x1 (POWERON_RESET),boot:0x13'), null);
  assert.equal(parseResponse(''), null);
  assert.equal(parseResponse('ets Jun  8 2016 00:22:57'), null);
});

test('the boot banner is not mistaken for a response', () => {
  // `SIOT READY PROVISION/1` is printed on boot for a human with a serial
  // monitor. It is addressed to us and is still not a reply to anything, so a
  // handshake that accepted it would pass before the board could answer.
  assert.equal(parseResponse(`SIOT READY ${PROTOCOL_BANNER}`), null);
});

/* --- handshake ----------------------------------------------------------- */

test('only the exact banner is accepted', () => {
  assert.equal(isSupportedBanner(parseResponse(`SIOT OK ${PROTOCOL_BANNER}`)), true);
  // A later protocol revision has to be recognised as one, not driven blindly.
  assert.equal(isSupportedBanner(parseResponse('SIOT OK PROVISION/2')), false);
  assert.equal(isSupportedBanner(parseResponse('SIOT OK')), false);
  assert.equal(isSupportedBanner(parseResponse('SIOT ERR BAD-COMMAND HELLO')), false);
});

/* --- read-id ------------------------------------------------------------- */

test('a blank board reads back as null, however it says so', () => {
  assert.equal(storedIdFrom(parseResponse('SIOT OK -')), null);
  assert.equal(storedIdFrom(parseResponse('SIOT OK')), null);
});

test('a provisioned board reads back its id', () => {
  assert.equal(storedIdFrom(parseResponse(`SIOT OK ${ID_A}`)), ID_A);
});

test('an error on read-id throws rather than reading as blank', () => {
  // The dangerous failure: an NVS error that returned null would look like a
  // blank board, and the next step would write over whatever is on it.
  assert.throws(() => storedIdFrom(parseResponse('SIOT ERR NVS could not open')));
});

/* --- the overwrite decision (design 5.4) --------------------------------- */

test('a blank board is provisioned normally', () => {
  assert.deepEqual(classifyBoard(null, null), {
    state: BLANK,
    storedId: null,
    storedName: null,
  });
});

test('the same id is a re-provision and proceeds', () => {
  const vault = [{ id: ID_A, name: 'Greenhouse humidity' }];
  assert.deepEqual(classifyBoard(ID_A, ID_A, vault), {
    state: SAME,
    storedId: ID_A,
    storedName: 'Greenhouse humidity',
  });
});

test('a different id is refused, and named when the vault knows it', () => {
  const vault = [{ id: ID_A, name: 'Greenhouse humidity' }];
  assert.deepEqual(classifyBoard(ID_A, ID_B, vault), {
    state: OCCUPIED,
    storedId: ID_A,
    storedName: 'Greenhouse humidity',
  });
});

test('an occupied board the vault has never heard of is still refused', () => {
  // The worse of the two cases, not the better one: it means the board belongs
  // to another account, or to a vault entry that has been lost. Having no name
  // must not make it read as the unremarkable branch.
  assert.deepEqual(classifyBoard(ID_A, ID_B, []), {
    state: OCCUPIED,
    storedId: ID_A,
    storedName: null,
  });
});

test('minting a new device can never match an occupied board', () => {
  // `intendedId` is null in the ordinary add flow, because the id does not exist
  // until it is generated. Every occupied board is therefore OCCUPIED, and SAME
  // only arises from re-provisioning an existing device (roadmap 8.4).
  assert.equal(classifyBoard(ID_A, null).state, OCCUPIED);
  assert.equal(classifyBoard(ID_B, null).state, OCCUPIED);
});

/* --- wording ------------------------------------------------------------- */

test('every error the sketch can send has wording, and none of it leaks the detail', () => {
  const codes = ['STALE', 'BAD-LENGTH', 'BAD-ARGS', 'BAD-COMMAND', 'TOO-LONG', 'NVS'];
  for (const code of codes) {
    const text = describeError({ ok: false, code, detail: 'device_id must be 16 bytes' });
    assert.ok(text.length > 0, `${code} has no wording`);
    // The board's detail is written for a log, not for a person.
    assert.doesNotMatch(text, /device_id must be/);
  }
});

test('an unrecognised code still says something rather than nothing', () => {
  assert.ok(describeError({ ok: false, code: 'FUTURE-CODE', detail: null }).length > 0);
});

test('STALE and NVS both promise that nothing was written', () => {
  // Both are refusals before or instead of a write, and the person needs to know
  // their vault and their board have not diverged.
  // Worded to cover the erase as well as the write, since both refusals mean the
  // same thing to a reader: the board is as it was.
  assert.match(describeError({ ok: false, code: 'STALE', detail: ID_A }), /[Nn]othing on it was changed/);
  assert.match(describeError({ ok: false, code: 'NVS', detail: null }), /[Nn]othing on it was changed/);
});
