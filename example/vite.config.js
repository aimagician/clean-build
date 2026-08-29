import { defineConfig } from 'vite';

export default defineConfig({
  // clean-builder passes --host/--port on the command line; nothing needed
  // here. Add proxy entries if your app talks to a local API — reach it via
  // `clean-builder proxy add <port> <ip:port>` and target 127.0.0.1:<port>.
  server: {}
});
