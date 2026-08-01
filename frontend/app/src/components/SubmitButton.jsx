/**
 * The primary action, with the honest waiting state attached.
 *
 * `busyLabel` replaces the label and the rust bar appears underneath while the
 * form is working. That wait is mostly Argon2id running on this machine, which
 * is the expensive step that makes the password worth anything — so it gets
 * named rather than hidden behind a spinner.
 */
export function SubmitButton({ children, busy, busyLabel, disabled }) {
  return (
    <div>
      <button className="button" type="submit" disabled={busy || disabled}>
        {busy ? busyLabel : children}
      </button>
      {busy ? (
        <div className="work-bar" role="progressbar" aria-label={busyLabel}>
          <div className="work-bar-mark" />
        </div>
      ) : null}
    </div>
  );
}
