import { syscallNumbers as syscallNumbersX86_64 } from "./x64.ts";
import { syscallNumbers as syscallNumbersArm64 } from "./arm64.ts";
import { syscallNumbers as syscallNumbersArm } from "./arm.ts";
import process from "node:process";

if (process.platform !== "linux") {
  throw Error("only supported on linux");
}

type TSyscallConstants = typeof syscallNumbersX86_64 | typeof syscallNumbersArm64 | typeof syscallNumbersArm;

const syscallNumbersByArch: Partial<{ [key in NodeJS.Architecture]: TSyscallConstants }> = {
  x64: syscallNumbersX86_64,
  arm64: syscallNumbersArm64,
  arm: syscallNumbersArm,
};

const syscallNumbers = syscallNumbersByArch[process.arch];
if (syscallNumbers === undefined) {
  throw Error(`unsupported architecture: ${process.arch}`);
}

export default syscallNumbers!;
