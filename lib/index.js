import { createRequire } from "module";
const require = createRequire(import.meta.url);

let native;

try {
  native = require("../build/Release/syscall.node");
} catch (ex) {
  native = require("../build/Debug/syscall.node");
}

const { syscall_async, syscall_sync, ...other } = native;

const syscall = (...args) => {
  return syscall_async(...args);
};
syscall.sync = (...args) => {
  return syscall_sync(...args);
};

export default {
  syscall,
  ...other
};
