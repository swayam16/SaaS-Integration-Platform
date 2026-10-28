import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies the backend from `syncbridge dev` (port 8080).
const backend = "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: Object.fromEntries(
      ["/api", "/saml", "/oauth", "/_idp", "/_sim", "/scim", "/webhooks"].map((p) => [p, backend]),
    ),
  },
  build: { outDir: "dist", sourcemap: false },
  test: { environment: "jsdom" },
});
