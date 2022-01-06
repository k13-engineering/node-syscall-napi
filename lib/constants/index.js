import x64 from "./x64.js";
import arm64 from "./arm64.js";
import arm from "./arm.js";

let syscallNumbers;

if (process.platform === "linux") {
  const syscallNumbersByArch = {
    x64,
    arm64,
    arm,
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
