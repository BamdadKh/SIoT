import Fastify from 'fastify';

const app = Fastify();
const port = 3030;

let numPressed = 0;

app.post('/button', async (_req, reply) => {
    numPressed++;
    console.log(`button pressed ${numPressed} time${numPressed>1 ? 's' : ''}`);
    reply.code(200).send();
});

app.listen({ port, host: '0.0.0.0' }, (err) => {
    if (err) {
        console.error('server failed to start:', err);
        process.exitCode = 1;
        return;
    }
    console.log(`server is listening on port ${port}`);
});
