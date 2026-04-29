import assert from "assert";
import { syscall, syscallNumbers } from "../lib/index.ts";
import { describe, it } from "mocha";

describe("basic", () => {
  it("should run getpid() correctly", () => {
    const { errno, ret: pid } = syscall({ syscallNumber: syscallNumbers.getpid, args: [] });
    assert.equal(errno, undefined);
    assert.equal(pid, process.pid);
  });

  it("should run clock_gettime() correctly via buffer passing", () => {
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
