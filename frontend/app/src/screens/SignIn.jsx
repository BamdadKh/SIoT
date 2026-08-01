import { useState } from 'react';
import { deriveAccountKeys, fromBase64Url, toBase64Url, unwrapVaultKey } from '@siot/crypto';
import { ApiError, fetchSalt, fetchWrappedVaultKey, logIn } from '../lib/api.js';
import { unlock } from '../lib/keyring.js';
import { Link } from '../lib/router.jsx';
import { Plate } from '../components/Plate.jsx';
import { Field } from '../components/Field.jsx';
import { SubmitButton } from '../components/SubmitButton.jsx';

/**
 * Sign in, which is mostly a local computation.
 *
 * The password is turned into a `master_key` here and split into two branches:
 * `login_key` goes to the server as proof, `kek` stays and opens the vault. The
 * server sees one of them and can do nothing with it but compare a hash.
 */
export function SignIn({ initialUsername = '', onSignedIn }) {
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  async function handleSubmit(event) {
    event.preventDefault();
    setError(null);

    let loginKey = null;
    let kek = null;
    let vaultKey = null;
    // Which step failed decides what the message can honestly say.
    let step = 'derive';

    try {
      setBusy('Working out your key');
      const { salt } = await fetchSalt(username.trim());
      ({ loginKey, kek } = await deriveAccountKeys(password, fromBase64Url(salt)));

      step = 'login';
      setBusy('Signing in');
      const session = await logIn(username.trim(), toBase64Url(loginKey));
      loginKey.fill(0);
      loginKey = null;

      step = 'unseal';
      const { wrapped_vault_key: wrapped } = await fetchWrappedVaultKey();
      vaultKey = await unwrapVaultKey(fromBase64Url(wrapped), kek);

      // The keyring owns both keys from here; drop our references without
      // zeroing them, or we would wipe the keys we just handed over.
      unlock(kek, vaultKey);
      kek = null;
      vaultKey = null;

      setPassword('');
      onSignedIn(session.username);
    } catch (failure) {
      setError(describe(failure, step));
      setBusy(null);
    } finally {
      loginKey?.fill(0);
      kek?.fill(0);
      vaultKey?.fill(0);
    }
  }

  const canSubmit = username.trim().length > 0 && password.length > 0;

  return (
    <Plate>
      <div className="wordmark" style={{ marginBottom: 'var(--sp-5)' }}>
        SIoT
      </div>
      <h1 className="h1">Sign in</h1>

      <form onSubmit={handleSubmit}>
        <div className="stack" style={{ gap: 'var(--sp-4)', marginTop: 'var(--sp-6)' }}>
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
            autoComplete="current-password"
          />
        </div>

        {error ? (
          <p className="alarm" style={{ marginTop: 'var(--sp-4)' }} role="alert">
            {error}
          </p>
        ) : null}

        <div style={{ marginTop: 'var(--sp-6)' }}>
          <SubmitButton busy={Boolean(busy)} busyLabel={busy} disabled={!canSubmit}>
            Sign in
          </SubmitButton>
        </div>
      </form>

      <hr className="rule" style={{ margin: 'var(--sp-6) 0 18px' }} />
      <p className="small" style={{ margin: 0 }}>
        No account yet? <Link to="/sign-up">Create one</Link>
      </p>
    </Plate>
  );
}

function describe(failure, step) {
  if (failure instanceof ApiError) {
    if (failure.status === 401) return 'That username and password do not match.';
    if (failure.status === 429) {
      const wait = failure.retryAfterSeconds;
      return wait
        ? `Too many attempts. Try again in ${wait} ${wait === 1 ? 'second' : 'seconds'}.`
        : 'Too many attempts. Try again shortly.';
    }
    if (failure.status === 0) return 'Could not reach the server.';
    return failure.message;
  }

  // Past the login call the password was right, so a failure here is the vault
  // blob itself, not the credentials. Say so rather than blaming the password.
  if (step === 'unseal') return 'Signed in, but your vault key would not open. Try again.';
  return 'Could not sign you in.';
}
