import { syscallNumbers } from "./constants/index.ts";

import { createRequire } from "module";
const require = createRequire(import.meta.url);

let native;

try {
  native = require("../build/Release/syscall.node");
} catch {
  native = require("../build/Debug/syscall.node");
}

const { syscall_sync } = native;

type TSyscallResult = {
  errno: undefined;
  ret: bigint;
} | {
  errno: number;
  ret: undefined;
}

const syscall = ({
  syscallNumber,
  args
}: {
  syscallNumber: bigint;
  args: (bigint | Uint8Array)[];
}): TSyscallResult => {
  const { errno, ret } = syscall_sync(syscallNumber, ...args);

  if (errno !== 0) {
    return {
      errno,
      ret: undefined
    };
  }

  return {
    errno: undefined,
    ret
  };
};

export {
  syscall,
  syscallNumbers
};
