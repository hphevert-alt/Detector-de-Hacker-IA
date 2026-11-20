import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import {defineConfig} from 'vite';

const pkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'package.json'), 'utf8'));
const gitSha = process.env.GITHUB_SHA ? process.env.GITHUB_SHA.slice(0, 7) : '';
const buildStamp =
  gitSha ||
  new Date()
    .toISOString()
    .replace(/[-:T]/g, '')
    .slice(0, 12);
const BUILD_VERSION = `v${pkg.version || '2.4.0'}-${buildStamp}`;

export default defineConfig(() => {
  return {
    base: './',
    define: {
      __AEGIS_BUILD_VERSION__: JSON.stringify(BUILD_VERSION),
    },
    plugins: [
      react(),
      tailwindcss(),
      // Copies src/assets into dist/ and stamps dist/sw.js cache version & built assets for GitHub Pages.
      {
        name: 'copy-unbundled-src-assets',
        apply: 'build',
        closeBundle(error?: Error): void {
          if (error) {
            return;
          }
          const distDir = path.resolve(__dirname, 'dist');
          const srcAssets = path.resolve(__dirname, 'src/assets');
          const distAssets = path.resolve(distDir, 'src/assets');
          if (fs.existsSync(distDir) && fs.existsSync(srcAssets)) {
            fs.cpSync(srcAssets, distAssets, {recursive: true, force: true});
          }

          const swPath = path.resolve(distDir, 'sw.js');
          if (fs.existsSync(swPath)) {
            const assetsDir = path.resolve(distDir, 'assets');
            const builtFiles = fs.existsSync(assetsDir)
              ? fs
                  .readdirSync(assetsDir)
                  .filter((name) => /\.(js|css|svg|png|woff2?)$/i.test(name))
                  .map((name) => `./assets/${name}`)
              : [];

            let swSource = fs.readFileSync(swPath, 'utf8');
            swSource = swSource
              .replace(
                /const CACHE_VERSION = '[^']*';/,
                `const CACHE_VERSION = '${BUILD_VERSION}';`
              )
              .replace(
                /const BUILD_ASSETS = \[[^\]]*\];/,
                `const BUILD_ASSETS = ${JSON.stringify(builtFiles)};`
              );
            fs.writeFileSync(swPath, swSource, 'utf8');
          }
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
