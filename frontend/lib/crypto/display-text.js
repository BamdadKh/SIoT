/**
 * The one cleaning rule for text a person typed and the app will later render:
 * device names, field labels, units.
 *
 * React escapes markup, so this is not an XSS defence and should not be mistaken
 * for one. It is a *display integrity* one: control characters and the Unicode
 * bidi overrides can make a string render as something other than its own bytes,
 * and zero-width characters make two different strings look identical. Shared
 * rather than copied so a name and a label cannot disagree about what is allowed.
 */

// C0/C1 controls, the bidi embedding and isolate overrides, and the zero-width
// characters that make two different strings look identical.
// eslint-disable-next-line no-control-regex -- stripping controls is the point
const INVISIBLE = /[\u0000-\u001F\u007F-\u009F​-‏‪-‮⁦-⁩﻿]/g;

/**
 * @param {string} text
 * @returns {string} the text with invisibles removed, whitespace runs collapsed,
 *          and the ends trimmed. May be empty; the caller decides whether that is
 *          allowed.
 */
export function cleanDisplayText(text) {
  return text.replace(INVISIBLE, '').replace(/\s+/g, ' ').trim();
}
