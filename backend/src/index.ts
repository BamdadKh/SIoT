import Fastify from 'fastify';

const app = Fastify();
const port = 1000;

app.post('/button', async (_req, reply) => {
    console.log('button pressed');
    reply.code(200).send();
});

app.listen({ port }, (err) => {
    if (err) {
        console.error('server failed to start:', err);
        process.exitCode = 1;
        return;
    }
    console.log(`server is listening on port ${port}`);
});
