# node-syscall-napi
Node.js module to perform promise-based asynchronous syscalls


## About

This module allows to execute syscalls on linux based systems. NAPI is being used to stay ABI compatible with future Node.js versions. The focus of this module is not (yet) performance, but providing a clear interface to the linux kernel.

## Requirements

- `Node.js >= 22` as this is a native TypeScript module

## Installation

```
npm install syscall-napi
```

or

```
yarn install syscall-napi
```

## API

### `syscall({ syscallNumber: bigint, args: (bigint | Uint8Array)[] })` => `{ errno: undefined, ret: BigInt } | { errno: number, ret: undefined }`

Supported argument types:
  - `BigInt` arguments are converted to native integers
  - `Buffer` arguments are converted to the address of the buffer in memory. Be aware that passing buffers of wrong sizes (i.e. smaller than the kernel expects) leads to undefined behaviour as it may overwrite vital data or crash the application.

In case of an error the promise is rejected with an error object.

For params see `man 2 syscall`.
  
### `syscallNumbers.{syscall}`
This module provides syscall numbers (e.g. `getpid`) that are defined in `uapi/asm-generic/unistd.h` in the linux kernel.

## Minimal example

```javascript
import { syscall, syscallNumbers } from "syscall-napi";

const { errno, ret: pid } = syscall({
  syscallNumber: syscallNumbers.__NR_getpid,
  args: []
});

if (errno === undefined) {
  console.log(`pid = ${pid}`);
} else {
  console.log(`errno = ${errno}`);
}
```
