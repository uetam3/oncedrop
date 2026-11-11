import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { resolve } from 'node:path';

// web/dist is not committed; only dist/.keep is, so that `go:embed all:dist`
// compiles without a frontend build. emptyOutDir removes it, so re-emit it.
const keepDist = {
  name: 'keep-dist',
  generateBundle() {
    this.emitFile({ type: 'asset', fileName: '.keep', source: '' });
  },
};

export default defineConfig({
  plugins: [preact(), keepDist],
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    rollupOptions: {
      input: {
        admin: resolve(import.meta.dirname, 'admin.html'),
        receive: resolve(import.meta.dirname, 'receive.html'),
      },
    },
  },
  server: {
    // `npm run dev` proxies API calls to a running oncedrop on its default
    // port, logged in with the key from ONCEDROP_KEY.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:47651',
        changeOrigin: true,
        headers: { Cookie: `od_admin_127_0_0_1_47651=${process.env.ONCEDROP_KEY || ''}` },
        configure: (proxy) => proxy.on('proxyReq', (req) => req.removeHeader('origin')),
      },
    },
  },
});
