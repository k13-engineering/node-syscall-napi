/* global describe */
/* global it */

import assert from "assert";
import sys from "../lib/index.js";

describe("basic", () => {
  it("should run getpid() correctly [async]", async () => {
    const pid = await sys.syscall(sys.__NR_getpid);
    assert.equal(pid, process.pid);
  });

  it("should run getpid() correctly [sync]", () => {
    const pid = sys.syscall.sync(sys.__NR_getpid);
    assert.equal(pid, process.pid);
  });
});
