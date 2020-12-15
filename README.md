# node-syscall-napi
Node.js module to perform promise-based asynchronous syscalls


## About

This module allows to execute syscalls on linux based systems. NAPI is being used to stay ABI compatible with future Node.js versions. The focus of this module is not (yet) performance, but providing a clear promise based interface to the linux kernel.

## Requirements

- `Node.js >= 12` as ES6 modules are used.

## Installation

```
npm install syscall-napi
```

or

```
yarn install syscall-napi
```

## API

### `sys.syscall(...params)` => `Promise(BigInt)`
Execute syscall asynchronously.

Supported argument types:
  - `BigInt` arguments are converted to native integers
  - `Buffer` arguments are converted to the address of the buffer in memory. The native code holds a reference to this buffer so it will not by freed by the garbage collector while the syscall is running. During a syscall the referenced buffer instance should not be modified. Be aware that passing buffers of wrong sizes (i.e. smaller than the kernel expects) leads to undefined behaviour as it may overwrite vital data or crash the application.

In case of an error the promise is rejected with an error object.

For params see `man 2 syscall`.
  
### `sys.__NR_xxx`
This module provides syscall numbers (e.g. `__NR_getpid`) that are defined in `uapi/asm-generic/unistd.h` in the linux kernel.

## Minimal example

```javascript
import sys from "syscall-napi";

process.nextTick(async () => {
  try {
    const pid = await sys.syscall(sys.__NR_getpid);
    console.log(`pid = ${pid}`);
  } catch (ex) {
    console.error(ex);
    process.exitCode = -1;
  }
});
```
