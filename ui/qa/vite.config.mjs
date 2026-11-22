// Fixture-only dev/build configuration; production configuration is unchanged.
import { mergeConfig } from "vite";
import base from "../vite.config.mjs";
import { fileURLToPath } from "node:url";
export default mergeConfig(base, {
  optimizeDeps: { noDiscovery: true, include: ['vue', 'vue-router', 'vue-i18n', '@carbon/vue'] },
  resolve: { alias: [{ find: /^\.\.\/task$/, replacement: fileURLToPath(new URL('./task-boundary.js', import.meta.url)) }] },
});
