import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Served from the backend at /_inspect/ — emit asset URLs accordingly so
  // the embedded build works without a reverse-proxy rewrite. Vite dev
  // (npm run dev) also serves under /_inspect/ because of this.
  base: "/_inspect/",
  server: {
    port: 5174,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
