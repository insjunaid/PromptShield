/// <reference types="vitest/config" />
import { readFileSync } from "node:fs";
import type { IncomingMessage } from "node:http";
import { fileURLToPath } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The API runs on 127.0.0.1:8000. Proxying /v1 (HTTP and WebSocket) keeps the browser on one origin,
// so development needs no extra CORS rules. The API still checks the Origin header on WebSockets.
const API = "http://127.0.0.1:8000";
const DASHBOARD_ORIGINS = new Set(["http://127.0.0.1:5173", "http://localhost:5173"]);
const TOKEN_FILE = fileURLToPath(new URL("../data/admin_token", import.meta.url));

/**
 * The API makes a fresh admin token at each start and writes it to data/admin_token. The proxy
 * hands it over for the dashboard's own changes (starting lab runs, approvals), read fresh each
 * time so an API restart needs no dashboard restart.
 *
 * Only requests whose Origin is the dashboard get it. A page from another site that posts here
 * carries its own Origin, gets no token, and the API turns it away.
 */
function adminToken(request: IncomingMessage): string | null {
  const mutating = request.method !== "GET" && request.method !== "HEAD" && request.method !== "OPTIONS";
  const origin = request.headers.origin;
  if (!mutating || origin === undefined || !DASHBOARD_ORIGINS.has(origin)) return null;
  try {
    return readFileSync(TOKEN_FILE, "utf-8").trim() || null;
  } catch {
    return null; // API not started yet: the request goes through without it and gets a 401
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/v1": {
        target: API,
        ws: true,
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyRequest, request) => {
            const token = adminToken(request);
            if (token !== null) proxyRequest.setHeader("X-Admin-Token", token);
          });
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test-setup.ts"],
  },
});
