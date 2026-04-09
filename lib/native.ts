import { createDefaultNativeAddonLoader } from "./snippets/native-loader.ts";

const nativeAddonLoader = createDefaultNativeAddonLoader({
  importMeta: import.meta,
  buildFolderPath: "../build",
});
const native = nativeAddonLoader.load() as Record<string, unknown>;

type TSyscallSync = (args: bigint, ...rest: (bigint | Uint8Array)[]) => { errno: number; ret?: bigint; };

const syscall_sync = native.syscall_sync as TSyscallSync;

export {
  syscall_sync
};
