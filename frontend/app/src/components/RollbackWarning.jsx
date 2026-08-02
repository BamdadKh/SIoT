/**
 * The vault came back older than one this browser has already opened (design
 * Section 8, roadmap 3.2).
 *
 * Rust rather than `--alarm`, and a plate rather than a note: this is not a
 * mistake the person made or a request they can retry, it is the one class of
 * tampering the AAD and the plaintext envelope in `vault.js` cannot catch on
 * their own, and the only useful instruction is to stop writing.
 *
 * Shared because every screen that reads the vault has to be able to render it,
 * and a screen that grew its own copy would be a screen that could get the copy
 * wrong.
 */
export function RollbackWarning({ serverVersion, cached }) {
  return (
    <section className="rollback-warning">
      <span className="tick tick-tl" />
      <span className="tick tick-tr" />
      <span className="tick tick-bl" />
      <span className="tick tick-br" />
      <h2 className="h3">This vault went backwards</h2>
      <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
        The server just returned vault version <span className="mono">{serverVersion}</span>, but
        this browser has already seen version <span className="mono">{cached}</span>. That can only
        happen if the server served an old copy of your vault, either by mistake or on purpose.
        Nothing has been decrypted or trusted.
      </p>
      <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
        Do not make changes to devices or credentials from this browser until this is resolved.
      </p>
    </section>
  );
}
