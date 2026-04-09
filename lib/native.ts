import { createDefaultNativeAddonLoader } from "./snippets/native-loader.ts";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";

const ourScriptPath = fileURLToPath(import.meta.url);
const ourScriptFolder = nodePath.dirname(ourScriptPath);
const isDistBuild = ourScriptFolder.endsWith("dist/lib");

const nativeAddonLoader = createDefaultNativeAddonLoader({
  importMeta: import.meta,
  buildFolderPath: isDistBuild ? "../../build" : "../build",
});
const native = nativeAddonLoader.load() as Record<string, unknown>;

type TSyscallSync = (args: bigint, ...rest: (bigint | Uint8Array)[]) => { errno: number; ret?: bigint; };

const syscall_sync = native.syscall_sync as TSyscallSync;

export {
  syscall_sync
};
