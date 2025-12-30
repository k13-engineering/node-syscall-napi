import { syscallNumbers } from "./constants/index.ts";
import { syscall_sync } from "./native.ts";

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

  // mainly for TypeScript type narrowing
  if (ret === undefined) {
    throw new Error("syscall returned undefined ret with errno 0");
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
