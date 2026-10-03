/// <reference types="vitest/config" />
// Vite serves the frontend to the webview in development (`pnpm tauri dev`
// starts it on port 1420, the `devUrl` of tauri.conf.json) and bundles it
// into dist/ for `pnpm tauri build`. Vitest runs the unit tests with the
// same configuration, in Node (a component test opts into jsdom).
import { fileURLToPath, URL } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  // Tauri prints its own output; keep Vite's on screen with it.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    // Rust changes are Tauri's to rebuild.
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: {
    // WebKitGTK 2.4x and later.
    target: "es2022",
    chunkSizeWarningLimit: 2000,
  },
  test: {
    // The logic tests need no DOM; a component test opts in with a
    // `// @vitest-environment jsdom` comment.
    environment: "node",
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
