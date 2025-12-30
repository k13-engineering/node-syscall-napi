import { syscallNumbers as syscallNumbersX86_64 } from "./x64.js";
import { syscallNumbers as syscallNumbersArm64 } from "./arm64.js";
import { syscallNumbers as syscallNumbersArm } from "./arm.js";

let syscallNumbers;

if (process.platform === "linux") {
  const syscallNumbersByArch = {
    x64: syscallNumbersX86_64,
    arm64: syscallNumbersArm64,
    arm: syscallNumbersArm,
  };
  syscallNumbers = syscallNumbersByArch[process.arch] || {};
} else {
  // how can you even load this?
  syscallNumbers = {};
}

if (process.platform !== "linux") {
  throw Error("on");
}

export default syscallNumbers;
