import assert from "assert";
import { syscall, syscallNumbers } from "../lib/index.ts";
import { describe, it } from "mocha";

describe("basic", () => {
  it("should run getpid() correctly", () => {
    const { errno, ret: pid } = syscall({ syscallNumber: syscallNumbers.getpid, args: [] });
    assert.equal(errno, undefined);
    assert.equal(pid, process.pid);
  });
});
