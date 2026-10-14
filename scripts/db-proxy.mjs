/* global console */
import net from 'node:net';

const server = net.createServer((socket) => {
  const remote = net.connect(5432, '127.0.0.1');
  socket.pipe(remote).pipe(socket);
  socket.on('error', () => {
    // ignore socket reset
  });
  remote.on('error', () => {
    // ignore remote reset
  });
});

server.listen(5431, '127.0.0.1', () => {
  console.log('Postgres proxy listening on 127.0.0.1:5431 -> 127.0.0.1:5432');
});
