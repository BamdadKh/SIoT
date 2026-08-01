import { useState } from 'react';
import {
  deriveAccountKeys,
  fromBase64Url,
  generateSalt,
  toBase64Url,
  wrapVaultKey,
} from '@siot/crypto';
import { ApiError, changePassword, fetchSalt } from '../lib/api.js';
import { getVaultKey } from '../lib/keyring.js';
import { Link } from '../lib/router.jsx';
import { Plate } from '../components/Plate.jsx';
import { Field } from '../components/Field.jsx';
import { SubmitButton } from '../components/SubmitButton.jsx';

const MIN_PASSWORD = 8;

/**
 * Re-wraps `vault_key` under a new `kek` (design Section 2.2, roadmap 3.3).
 * Vault contents never move: this is 92 bytes of key material, not a vault
 * write, and `PUT /vault` is not involved.
 *
 * A focused, single-purpose authenticated screen, so it uses `Plate` the same
 * way `Unlock` does rather than the `TopBar` shell `Devices` uses for the main
 * app view: one action, centred, with account controls in a footer row below
 * a rule instead of a header bar.
 *
 * Only reachable while unlocked (`App.jsx` routes here from the unlocked
 * branch), so this tab has already proven the current password to itself by
 * having a `vault_key` in memory at all. That proof never reached the server,
 * though, which is why the form still asks for the current password: the
 * server checks it against `login_key_hash` before accepting anything, the
 * same way `/login` does.
 */
export function ChangePassword({ username, onSignOut, signingOut }) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();

    const complaint = check(newPassword, confirmation);
    if (complaint) {
      setError(complaint);
      setDone(false);
      return;
    }
    setError(null);
    setDone(false);

    let currentLoginKey = null;
    let currentKek = null;
    let newSalt = null;
    let newLoginKey = null;
    let newKek = null;

    try {
      setBusy('Checking your current password');
      const { salt: currentSalt } = await fetchSalt(username);
      ({ loginKey: currentLoginKey, kek: currentKek } = await deriveAccountKeys(
        currentPassword,
        fromBase64Url(currentSalt),
      ));
      // Only `login_key` is wanted here. Proving the current password is the
      // server's job, not this tab's, and this tab's own `kek` never changes
      // as a result of this call.
      currentKek.fill(0);
      currentKek = null;

      setBusy('Working out your new key');
      newSalt = generateSalt();
      ({ loginKey: newLoginKey, kek: newKek } = await deriveAccountKeys(newPassword, newSalt));

      // The vault_key itself is unchanged. Only the wrapping around it moves
      // to the new kek. It stays in the keyring throughout; this call never
      // touches vault contents.
      const wrapped = await wrapVaultKey(getVaultKey(), newKek);

      setBusy('Saving');
      await changePassword({
        current_login_key: toBase64Url(currentLoginKey),
        salt: toBase64Url(newSalt),
        login_key: toBase64Url(newLoginKey),
        wrapped_vault_key: toBase64Url(wrapped),
      });

      setCurrentPassword('');
      setNewPassword('');
      setConfirmation('');
      setDone(true);
    } catch (failure) {
      setError(describe(failure));
    } finally {
      setBusy(null);
      currentLoginKey?.fill(0);
      currentKek?.fill(0);
      newLoginKey?.fill(0);
      newKek?.fill(0);
    }
  }

  const canSubmit = currentPassword && newPassword && confirmation;

  return (
    <Plate>
      <div className="wordmark" style={{ marginBottom: 'var(--sp-5)' }}>
        SIoT
      </div>
      <h1 className="h1">Change password</h1>
      <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
        This trades your current password for a new one. There is still no reset, so losing the
        new one loses the vault the same way losing the old one would.
      </p>

      <form onSubmit={handleSubmit}>
        <div className="stack" style={{ gap: 'var(--sp-4)', marginTop: 'var(--sp-5)' }}>
          <Field
            label="Current password"
            type="password"
            value={currentPassword}
            onChange={setCurrentPassword}
            disabled={Boolean(busy)}
            autoComplete="current-password"
            autoFocus
          />
          <Field
            label="New password"
            type="password"
            value={newPassword}
            onChange={setNewPassword}
            disabled={Boolean(busy)}
            autoComplete="new-password"
          />
          <Field
            label="New password again"
            type="password"
            value={confirmation}
            onChange={setConfirmation}
            disabled={Boolean(busy)}
            autoComplete="new-password"
          />
        </div>

        {error ? (
          <p className="alarm" style={{ marginTop: 'var(--sp-4)' }} role="alert">
            {error}
          </p>
        ) : null}

        {done ? (
          <p className="success" style={{ marginTop: 'var(--sp-4)' }} role="status">
            Password changed. Use the new one next time you unlock.
          </p>
        ) : null}

        <div style={{ marginTop: 'var(--sp-5)' }}>
          <SubmitButton busy={Boolean(busy)} busyLabel={busy} disabled={!canSubmit}>
            Change password
          </SubmitButton>
        </div>
      </form>

      <hr className="rule" style={{ margin: 'var(--sp-6) 0 18px' }} />
      <div className="row spread">
        <span className="small">
          Signed in as <span className="mono">{username}</span>
        </span>
        <div className="row" style={{ gap: 'var(--sp-4)' }}>
          <Link to="/" className="button button-link">
            Devices
          </Link>
          <button className="button button-link" type="button" onClick={onSignOut} disabled={signingOut}>
            {signingOut ? 'Signing out' : 'Sign out'}
          </button>
        </div>
      </div>
    </Plate>
  );
}

function check(newPassword, confirmation) {
  if (newPassword.length < MIN_PASSWORD) {
    return `Use at least ${MIN_PASSWORD} characters.`;
  }
  if (newPassword !== confirmation) {
    return 'Those two new passwords are not the same.';
  }
  return null;
}

function describe(failure) {
  if (failure instanceof ApiError) {
    if (failure.status === 403) return 'Your current password is incorrect.';
    if (failure.status === 429) {
      return `Too many attempts. Try again in ${failure.retryAfterSeconds ?? 'a bit'}s.`;
    }
    if (failure.status === 401) return 'Your session ended. Sign in again.';
    if (failure.status === 0) return 'Could not reach the server.';
    return failure.message;
  }
  return 'Could not change your password.';
}
