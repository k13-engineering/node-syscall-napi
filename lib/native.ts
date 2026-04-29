import { loadAddonFromMemory } from "./load-addon-from-memory.ts";
import { syscallAddonArm64 } from "./generated/syscall-arm64.ts";
import { syscallAddonX64 } from "./generated/syscall-x64.ts";
import nodeProcess from "node:process";

type TSyscallAddon = {
  syscall_sync: (args: bigint, ...rest: (bigint | Uint8Array)[]) => { errno: number; ret?: bigint; };
};

const addonBinariesByArch: Partial<{ [key in NodeJS.Architecture]: Uint8Array }> = {
  x64: syscallAddonX64,
  arm64: syscallAddonArm64,
};

let loadedAddon: TSyscallAddon | undefined = undefined;

// eslint-disable-next-line complexity
const syscall_sync: TSyscallAddon["syscall_sync"] = (...args) => {
  if (loadedAddon !== undefined) {
    return loadedAddon.syscall_sync(...args);
  }

  if (nodeProcess.platform !== "linux") {
    throw Error("only supported on linux");
  }

  const addonBinary = addonBinariesByArch[nodeProcess.arch];
  if (addonBinary === undefined) {
    throw Error(`unsupported architecture: ${nodeProcess.arch}`);
  }

  const { error, addon } = loadAddonFromMemory({ addonAsBuffer: addonBinary });
  if (error !== undefined) {
    throw Error(`failed to load native addon from memory: ${error.message}`);
  }

  loadedAddon = addon as TSyscallAddon;
  return loadedAddon.syscall_sync(...args);
};

export {
  syscall_sync
};
