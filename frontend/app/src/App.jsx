import { useCallback, useEffect, useState, useSyncExternalStore } from 'react';
import { fetchSession, logOut } from './lib/api.js';
import { clear, isUnlocked, subscribe } from './lib/keyring.js';
import { navigate, usePath } from './lib/router.jsx';
import { SignIn } from './screens/SignIn.jsx';
import { SignUp } from './screens/SignUp.jsx';
import { Unlock } from './screens/Unlock.jsx';
import { Devices } from './screens/Devices.jsx';

/**
 * Which screen to show is decided by two independent facts, not one:
 *
 *   is there a session?   the cookie, which survives a reload
 *   is the vault open?    `kek` in memory, which does not
 *
 * Most apps only have the first. Here the pair (session, locked) is a real
 * state the user lands in every time they refresh, so it gets its own screen
 * rather than being papered over with a redirect to sign-in.
 */
export function App() {
  const path = usePath();
  const unlocked = useSyncExternalStore(subscribe, isUnlocked);

  const [session, setSession] = useState({ status: 'checking' });
  const [signingOut, setSigningOut] = useState(false);
  const [knownUsername, setKnownUsername] = useState('');

  useEffect(() => {
    let live = true;
    fetchSession()
      .then((who) => live && setSession({ status: 'in', username: who.username }))
      .catch(() => live && setSession({ status: 'out' }));
    return () => {
      live = false;
    };
  }, []);

  const handleSignedIn = useCallback((username) => {
    setSession({ status: 'in', username });
    navigate('/', { replace: true });
  }, []);

  const handleSignOut = useCallback(async () => {
    setSigningOut(true);
    try {
      await logOut();
    } catch {
      // The cookie is dead either way once the keys are gone; a failed request
      // must not strand the person on a screen they cannot leave.
    } finally {
      clear();
      setSession({ status: 'out' });
      setSigningOut(false);
      navigate('/sign-in', { replace: true });
    }
  }, []);

  if (session.status === 'checking') {
    // One request, usually under a tenth of a second. A spinner here would
    // flash more often than it informs.
    return null;
  }

  if (session.status === 'out') {
    return path === '/sign-up' ? (
      <SignUp onSignedUp={setKnownUsername} />
    ) : (
      <SignIn initialUsername={knownUsername} onSignedIn={handleSignedIn} />
    );
  }

  if (!unlocked) {
    return (
      <Unlock
        username={session.username}
        onUnlocked={() => navigate('/', { replace: true })}
        onSignOut={handleSignOut}
        signingOut={signingOut}
      />
    );
  }

  return (
    <Devices username={session.username} onSignOut={handleSignOut} signingOut={signingOut} />
  );
}
