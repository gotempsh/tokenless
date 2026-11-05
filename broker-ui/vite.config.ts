// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the API runs on 127.0.0.1:8080 (`credential-broker serve`).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { "/api": "http://127.0.0.1:8080" },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
