import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the API runs on :8000. The proxy keeps everything same-origin so the
// SameSite=Strict session cookie works exactly as it does in production.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": "http://localhost:8000" } },
});
