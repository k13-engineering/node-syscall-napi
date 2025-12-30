import { syscallNumbers as syscallNumbersX86_64 } from "./x64.ts";
import { syscallNumbers as syscallNumbersArm64 } from "./arm64.ts";
import { syscallNumbers as syscallNumbersArm } from "./arm.ts";
import nodeProcess from "node:process";

if (nodeProcess.platform !== "linux") {
  throw Error("only supported on linux");
}

type Common<T, U> = Pick<T, Extract<keyof T, keyof U>>;

type TCommonSyscallConstants = Common<Common<typeof syscallNumbersX86_64, typeof syscallNumbersArm64>, typeof syscallNumbersArm>;

type TSyscallConstants = TCommonSyscallConstants &
  (Partial<typeof syscallNumbersX86_64> & Partial<typeof syscallNumbersArm64> & Partial<typeof syscallNumbersArm>);

const syscallNumbersByArch: Partial<{ [key in NodeJS.Architecture]: TSyscallConstants }> = {
  x64: syscallNumbersX86_64,
  arm64: syscallNumbersArm64,
  arm: syscallNumbersArm,
};

const syscallNumbersOfArch = syscallNumbersByArch[nodeProcess.arch];
if (syscallNumbersOfArch === undefined) {
  throw Error(`unsupported architecture: ${nodeProcess.arch}`);
}

const syscallNumbers = syscallNumbersOfArch!;

export {
  syscallNumbers
};
