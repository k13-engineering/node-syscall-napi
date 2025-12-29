import constants from "./constants/index.js";

import { createRequire } from "module";
const require = createRequire(import.meta.url);

let native;

try {
  native = require("../build/Release/syscall.node");
} catch {
  native = require("../build/Debug/syscall.node");
}

const { syscall_sync } = native;

const syscall = (...args) => {
  return syscall_sync(...args);
};

export default {
  syscall,
  ...constants,
};
