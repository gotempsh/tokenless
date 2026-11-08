// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In development the API runs on 127.0.0.1:8080 (`tokenless serve`);
// TOKENLESS_API points the dev server at another one.
const api = process.env.TOKENLESS_API ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: { "/api": api },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
