import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const here = (rel) => fileURLToPath(new URL(rel, import.meta.url));

/**
 * Every path the backend owns. Anything not listed here is served by Vite as an
 * app route, so adding a server endpoint means adding it here too — a missing
 * entry shows up as index.html arriving where JSON was expected.
 *
 * `/logout` covers `/logout-everywhere`; these are prefix matches.
 */
const API_PATHS = [
  '/health',
  '/signup',
  '/salt',
  '/login',
  '/session',
  '/logout',
  '/vault-key',
  '/vault',
];

/**
 * The dev server runs HTTPS off the backend's own certificate, and it is not
 * optional. The session cookie is `Secure; SameSite=Strict`, so over plain HTTP
 * the browser drops it silently and every authenticated request 401s with no
 * visible cause. Same cert as the backend means one trust prompt, not two.
 */
function devCertificate() {
  const cert = here('../backend/certs/dev-cert.pem');
  const key = here('../backend/certs/dev-key.pem');

  if (!fs.existsSync(cert) || !fs.existsSync(key)) {
    throw new Error(
      'dev TLS certificate not found.\n' +
        'Run `npm run gen-cert` in ../backend first — the dev server cannot run ' +
        'over plaintext, because the session cookie is Secure.',
    );
  }
  return { cert: fs.readFileSync(cert), key: fs.readFileSync(key) };
}

export default defineConfig({
  root: 'app',
  plugins: [react()],
  resolve: {
    /**
     * The crypto stays at `frontend/lib/crypto/`, outside the app root, and is
     * reached by one alias rather than by `../../../lib` from every screen.
     * Keeping it out of `app/` is the point: `node --test` runs those exact
     * files, so the modules the tests cover are byte-identical to the ones the
     * browser loads — no bundler-only copy that could drift.
     */
    alias: { '@siot/crypto': here('lib/crypto/index.js') },
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    https: devCertificate(),
    // The alias resolves above `root`, which the dev server refuses to serve
    // from unless the parent is allowed explicitly.
    fs: { allow: [here('.')] },
    proxy: Object.fromEntries(
      API_PATHS.map((path) => [
        path,
        {
          target: 'https://localhost:3030',
          // The backend presents the same self-signed certificate we are serving
          // with; there is no CA to chain it to.
          secure: false,
        },
      ]),
    ),
  },
});
