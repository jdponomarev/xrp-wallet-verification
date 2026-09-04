import { defineConfig } from 'vite';
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const commit = (() => {
  try {
    return execSync('git rev-parse --short HEAD').toString().trim();
  } catch {
    return 'unknown';
  }
})();
const coreVersion = JSON.parse(
  readFileSync(new URL('../core/package.json', import.meta.url), 'utf8'),
).version as string;

export default defineConfig({
  // Project page: https://jdponomarev.github.io/xrp-wallet-verification/
  base: '/xrp-wallet-verification/',
  define: {
    __COMMIT__: JSON.stringify(commit),
    __CORE_VERSION__: JSON.stringify(coreVersion),
  },
  build: { target: 'es2022', sourcemap: true },
});
