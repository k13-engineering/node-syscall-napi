/* global describe */
/* global it */

import assert from "assert";
import { syscall, syscallNumbers } from "../lib/index.ts";

describe("basic", () => {
  it("should run getpid() correctly", () => {
    const { errno, ret: pid } = syscall({ syscallNumber: syscallNumbers.getpid, args: [] });
    assert.equal(errno, undefined);
    assert.equal(pid, process.pid);
  });
});
