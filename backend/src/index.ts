import { buildApp } from './app.js';
import { config } from './config.js';

async function main() {
  const app = await buildApp();

  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => {
      app.log.info(`${signal} received, shutting down`);
      app.close().then(
        () => process.exit(0),
        (err) => {
          app.log.error(err, 'error during shutdown');
          process.exit(1);
        },
      );
    });
  }

  await app.listen({ port: config.port, host: config.host });
}

main().catch((err) => {
  console.error('server failed to start:', err);
  process.exit(1);
});
