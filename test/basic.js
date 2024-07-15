/* global describe */
/* global it */

import assert from "assert";
import sys from "../lib/index.js";

describe("basic", () => {
  it("should run getpid() correctly [async]", async () => {
    const { errno, ret: pid } = await sys.syscall(sys.__NR_getpid);
    assert.equal(errno, 0);
    assert.equal(pid, process.pid);
  });

  it("should run getpid() correctly [sync]", () => {
    const { errno, ret: pid } = sys.syscall.sync(sys.__NR_getpid);
    assert.equal(errno, 0);
    assert.equal(pid, process.pid);
  });
});
