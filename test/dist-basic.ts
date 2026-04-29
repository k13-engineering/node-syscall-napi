import assert from "assert";
import { existsSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { describe, it } from "mocha";

const distDir = resolve(dirname(fileURLToPath(import.meta.url)), "../dist");
const hasDistDir = existsSync(distDir);

(hasDistDir ? describe : describe.skip)("basic [dist]", () => {
  it("should run getpid() correctly", async () => {
    const { syscall, syscallNumbers } = await import("../dist/lib/index.js");
    const { errno, ret: pid } = syscall({ syscallNumber: syscallNumbers.getpid, args: [] });
    assert.equal(errno, undefined);
    assert.equal(pid, process.pid);
  });

  it("should run clock_gettime() correctly via buffer passing", async () => {
    const { syscall, syscallNumbers } = await import("../dist/lib/index.js");
    const CLOCK_REALTIME = 0n;
    const buf = new Uint8Array(16);
    const { errno } = syscall({ syscallNumber: syscallNumbers.clock_gettime, args: [CLOCK_REALTIME, buf] });
    assert.equal(errno, undefined);

    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const tv_sec = view.getBigInt64(0, true);
    const tv_nsec = view.getBigInt64(8, true);

    assert.ok(tv_nsec >= 0n && tv_nsec < 1_000_000_000n, `tv_nsec out of range: ${tv_nsec}`);

    const syscallTimeMs = Number(tv_sec) * 1000 + Number(tv_nsec) / 1_000_000;
    const nodeTimeMs = Date.now();
    const diffMs = Math.abs(syscallTimeMs - nodeTimeMs);
    assert.ok(diffMs < 30_000, `clock_gettime and Date.now() differ by ${diffMs}ms, expected < 30000ms`);
  });
});
