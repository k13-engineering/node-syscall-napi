import { createRequire } from "module";
const require = createRequire(import.meta.url);

let native;

try {
  native = require("../build/Release/syscall.node");
} catch (ex) {
  native = require("../build/Debug/syscall.node");
}

export default native;
