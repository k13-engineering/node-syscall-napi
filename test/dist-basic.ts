/* global describe */
/* global it */

import assert from "assert";
import { existsSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const distDir = resolve(dirname(fileURLToPath(import.meta.url)), "../dist");
const hasDistDir = existsSync(distDir);

(hasDistDir ? describe : describe.skip)("basic [dist]", () => {
  it("should run getpid() correctly", async () => {
    const { syscall, syscallNumbers } = await import("../dist/lib/index.js");
    const { errno, ret: pid } = syscall({ syscallNumber: syscallNumbers.getpid, args: [] });
    assert.equal(errno, undefined);
    assert.equal(pid, process.pid);
  });
});
