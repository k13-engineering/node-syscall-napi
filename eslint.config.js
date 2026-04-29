/* c8 ignore start */
import { defineConfig } from "eslint/config";
import { createEslintConfig } from "@k13engineering/eslint-rules";

// eslint-disable-next-line k13-engineering/no-default-export
export default defineConfig([
  {
    ignores: [
      "dist/**/*",
    ],
  },
  ...createEslintConfig(),
]);
/* c8 ignore stop */
