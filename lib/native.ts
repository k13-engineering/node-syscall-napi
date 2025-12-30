import { createNativeAddonLoader } from "./snippets/native-loader.ts";

const nativeAddonLoader = createNativeAddonLoader();
const native = nativeAddonLoader.loadRelativeToPackageRoot({
    relativeBuildFolderPath: "./build"
});

type TSyscallSync = (args: bigint, ...rest: (bigint | Uint8Array)[]) => { errno: number; ret?: bigint; };

const syscall_sync = native.syscall_sync as TSyscallSync;

export {
    syscall_sync
};
