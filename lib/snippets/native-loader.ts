import nodeFs from "node:fs";
import nodeUrl from "node:url";
import nodePath from "node:path";
import nodeModule from "node:module";

type TFileSystemInterface = {
  existsSync: (path: string) => boolean;
  readdirSync: (path: string) => string[];
};

type TSystemInterface = {
  fileSystem: TFileSystemInterface;
  loadAddonAtPath: (options: { addonFilePath: string }) => unknown;
};

const createNativeAddonLoader = ({
  systemInterface,
  importMeta,
  buildFolderPath: providedBuildFolderPath,
}: {
  systemInterface: TSystemInterface;
  importMeta: { url: string };
  buildFolderPath: string;
}) => {

  const scriptPath = nodeUrl.fileURLToPath(importMeta.url);
  const scriptDirectory = nodePath.dirname(scriptPath);
  const resolvedBuildFolderPath = nodePath.join(scriptDirectory, providedBuildFolderPath);

  const findAddonInAddonFolder = ({ addonFolderPath }: { addonFolderPath: string }) => {
    const entries = systemInterface.fileSystem.readdirSync(addonFolderPath);

    const addonEntries = entries.filter((entry) => {
      return entry.endsWith(".node");
    });

    if (addonEntries.length === 0) {
      throw Error(`no .node addon file found in build folder "${addonFolderPath}"`);
    }

    if (addonEntries.length > 1) {
      throw Error(`multiple .node addon files found in build folder "${addonFolderPath}", cannot determine which to load`);
    }

    const addonFileName = addonEntries[0];

    return addonFileName;
  };

  const assertOnlyOneOfDebugOrReleaseExists = ({
    debugFolderExists,
    releaseFolderExists
  }: {
    debugFolderExists: boolean;
    releaseFolderExists: boolean
  }) => {
    if (debugFolderExists && releaseFolderExists) {
      throw Error(`both Debug and Release build folders exist, please remove one to avoid ambiguity`);
    }
  };

  const assertAtLeastOneOfDebugOrReleaseExists = ({
    debugFolderExists,
    releaseFolderExists
  }: {
    debugFolderExists: boolean;
    releaseFolderExists: boolean
  }) => {
    if (!debugFolderExists && !releaseFolderExists) {
      throw Error(`neither Debug nor Release build folders found, make sure to build the native addon first`);
    }
  };

  const determineReleaseOrDebugFolder = ({ buildFolderPath }: { buildFolderPath: string }) => {
    const debugFolderPath = nodePath.join(buildFolderPath, "Debug");
    const releaseFolderPath = nodePath.join(buildFolderPath, "Release");

    const debugFolderExists = systemInterface.fileSystem.existsSync(debugFolderPath);
    const releaseFolderExists = systemInterface.fileSystem.existsSync(releaseFolderPath);

    try {
      assertAtLeastOneOfDebugOrReleaseExists({ debugFolderExists, releaseFolderExists });
      assertOnlyOneOfDebugOrReleaseExists({ debugFolderExists, releaseFolderExists });
    } catch (ex) {
      throw Error(`invalid build folder structure at "${buildFolderPath}"`, { cause: ex });
    }

    const addonFolderPath = releaseFolderExists ? releaseFolderPath : debugFolderPath;

    return addonFolderPath;
  };

  const loadAddonFromFolder = ({ addonFolderPath }: { addonFolderPath: string }) => {
    const addonFileName = findAddonInAddonFolder({ addonFolderPath });

    const addonFilePath = nodePath.resolve(addonFolderPath, addonFileName);

    const native = systemInterface.loadAddonAtPath({ addonFilePath });

    return native;
  };

  const load = () => {
    if (!systemInterface.fileSystem.existsSync(resolvedBuildFolderPath)) {
      throw Error(`no build folder found at "${resolvedBuildFolderPath}", make sure to build the native addon first`);
    }

    const addonFolderPath = determineReleaseOrDebugFolder({ buildFolderPath: resolvedBuildFolderPath });
    const native = loadAddonFromFolder({ addonFolderPath });

    return native;
  };

  return {
    load,
  };
};

const createDefaultSystemInterface = ({ importMeta }: { importMeta: { url: string } }): TSystemInterface => {

  /* c8 ignore start */
  const existsSync: TFileSystemInterface["existsSync"] = (path) => {
    return nodeFs.existsSync(path);
  };

  const readdirSync: TFileSystemInterface["readdirSync"] = (path) => {
    return nodeFs.readdirSync(path);
  };
  /* c8 ignore end */

  const fileSystem: TFileSystemInterface = {
    existsSync,
    readdirSync,
  };

  /* c8 ignore start */
  const loadAddonAtPath: TSystemInterface["loadAddonAtPath"] = ({ addonFilePath }) => {
    const require = nodeModule.createRequire(importMeta.url);
    const native = require(addonFilePath);
    return native;
  };
  /* c8 ignore end */

  return {
    fileSystem,
    loadAddonAtPath,
  };
};

const createDefaultNativeAddonLoader = ({ importMeta, buildFolderPath }: { importMeta: { url: string }; buildFolderPath: string }) => {
  const systemInterface = createDefaultSystemInterface({ importMeta });

  const nativeAddonLoader = createNativeAddonLoader({
    systemInterface,
    importMeta,
    buildFolderPath,
  });

  return nativeAddonLoader;
};

export {
  createNativeAddonLoader,
  createDefaultNativeAddonLoader
};
