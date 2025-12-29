/* global describe */
/* global it */

import assert from "assert";
import sys from "../lib/index.js";

describe("basic", () => {
  it("should run getpid() correctly", () => {
    const { errno, ret: pid } = sys.syscall(sys.__NR_getpid);
    assert.equal(errno, 0);
    assert.equal(pid, process.pid);
  });
});
