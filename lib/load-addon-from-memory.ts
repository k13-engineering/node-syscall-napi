import nodeProcess from "node:process";
import { binaryToFd, fdToProcfsPath } from "./binary-to-fd.ts";
import nodeFs from "node:fs";

type TLoadAddonFromMemoryResult = {
  error: Error,
  addon: undefined;
} | {
  error: undefined,
  addon: unknown;
};

const loadAddonFromMemory = ({ addonAsBuffer }: { addonAsBuffer: Uint8Array }): TLoadAddonFromMemoryResult => {
  const { fd } = binaryToFd({ binary: addonAsBuffer });

  try {
    const filepath = fdToProcfsPath({ fd });

    const module = { exports: {} };

    nodeProcess.dlopen(module, filepath);

    return {
      error: undefined,
      addon: module.exports
    };
  } catch (ex) {
    return {
      error: ex as Error,
      addon: undefined
    };
  } finally {
    nodeFs.closeSync(fd);
  }
};

export {
  loadAddonFromMemory
};
