import { syscall, syscallNumbers } from "../lib/index.ts";

const { errno, ret: pid } = syscall({
  syscallNumber: syscallNumbers.getpid,
  args: []
});

if (errno === undefined) {
  console.log(`pid = ${pid}`);
} else {
  console.log(`errno = ${errno}`);
}
