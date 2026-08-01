import { useState } from 'react';
import {
  deriveAccountKeys,
  generateSalt,
  generateVaultKey,
  toBase64Url,
  wrapVaultKey,
} from '@siot/crypto';
import { ApiError, signUp } from '../lib/api.js';
import { Link, navigate } from '../lib/router.jsx';
import { Plate } from '../components/Plate.jsx';
import { Field } from '../components/Field.jsx';
import { SubmitButton } from '../components/SubmitButton.jsx';

/** Mirrors the server's schema, so a bad name fails here instead of as a 400. */
const USERNAME = /^[A-Za-z0-9_.-]{3,32}$/;
const MIN_PASSWORD = 8;

/**
 * Create an account.
 *
 * Everything that matters happens before the request: the salt, the key
 * hierarchy, a fresh `vault_key`, and that key sealed under `kek`. What gets
 * posted is a username and three opaque blobs. There is no step at which the
 * server could have derived any of it itself.
 */
export function SignUp({ onSignedUp }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  async function handleSubmit(event) {
    event.preventDefault();

    const name = username.trim();
    const complaint = check(name, password, confirmation);
    if (complaint) {
      setError(complaint);
      return;
    }
    setError(null);

    let salt = null;
    let loginKey = null;
    let kek = null;
    let vaultKey = null;

    try {
      setBusy('Working out your key');
      salt = generateSalt();
      ({ loginKey, kek } = await deriveAccountKeys(password, salt));

      // Generated once, here, and never again: regenerating it would orphan
      // every record the vault points at.
      vaultKey = generateVaultKey();
      const wrapped = await wrapVaultKey(vaultKey, kek);

      setBusy('Creating your account');
      const created = await signUp({
        username: name,
        salt: toBase64Url(salt),
        login_key: toBase64Url(loginKey),
        wrapped_vault_key: toBase64Url(wrapped),
      });

      // No session comes back. Signing in is a separate, rate-limited step, and
      // keeping one way in is worth the extra form.
      setPassword('');
      setConfirmation('');
      onSignedUp(created.username);
      navigate('/sign-in');
    } catch (failure) {
      setError(describe(failure));
      setBusy(null);
    } finally {
      loginKey?.fill(0);
      kek?.fill(0);
      vaultKey?.fill(0);
    }
  }

  const canSubmit = username.trim() && password && confirmation;

  return (
    <Plate>
      <div className="wordmark" style={{ marginBottom: 'var(--sp-5)' }}>
        SIoT
      </div>
      <h1 className="h1">Create an account</h1>
      <p className="prose" style={{ marginTop: 'var(--sp-3)' }}>
        Your password cannot be reset. It is the only thing that opens your data, and no copy
        of it reaches the server.
      </p>

      <form onSubmit={handleSubmit}>
        <div className="stack" style={{ gap: 'var(--sp-4)', marginTop: 'var(--sp-5)' }}>
          <Field
            label="Username"
            value={username}
            onChange={setUsername}
            disabled={Boolean(busy)}
            autoComplete="username"
            autoFocus
          />
          <Field
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            disabled={Boolean(busy)}
            autoComplete="new-password"
          />
          <Field
            label="Password again"
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

        <div style={{ marginTop: 'var(--sp-5)' }}>
          <SubmitButton busy={Boolean(busy)} busyLabel={busy} disabled={!canSubmit}>
            Create account
          </SubmitButton>
        </div>
      </form>

      <hr className="rule" style={{ margin: 'var(--sp-6) 0 18px' }} />
      <p className="small" style={{ margin: 0 }}>
        Already have one? <Link to="/sign-in">Sign in</Link>
      </p>
    </Plate>
  );
}

function check(name, password, confirmation) {
  if (!USERNAME.test(name)) {
    return 'Usernames are 3 to 32 characters, using letters, digits, underscore, dot or hyphen.';
  }
  if (password.length < MIN_PASSWORD) {
    return `Use at least ${MIN_PASSWORD} characters. There is no reset, so pick something you will not lose.`;
  }
  if (password !== confirmation) {
    return 'Those two passwords are not the same.';
  }
  return null;
}

function describe(failure) {
  if (failure instanceof ApiError) {
    if (failure.status === 409) return 'That username is taken.';
    if (failure.status === 0) return 'Could not reach the server.';
    return failure.message;
  }
  return 'Could not create your account.';
}
