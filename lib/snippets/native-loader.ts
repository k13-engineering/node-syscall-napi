import nodeFs from "node:fs";
import nodeUrl from "node:url";
import nodePath from "node:path";
import nodeModule from "node:module";

const findPackageJson = ({ startPath, maxUpwardSteps }: { startPath: string; maxUpwardSteps: number }) => {
  let currentPath = startPath;

  for (let i = 0; i < maxUpwardSteps; i += 1) {
    const packageJsonPath = nodePath.join(currentPath, "package.json");

    if (nodeFs.existsSync(packageJsonPath)) {
      return packageJsonPath;
    }

    const parentPath = nodePath.dirname(currentPath);

    // Reached filesystem root
    if (parentPath === currentPath) {
      break;
    }

    currentPath = parentPath;
  }

  throw new Error(`Could not find package.json within ${maxUpwardSteps} directory levels from ${startPath}`);
};

const findPackageRoot = ({ maxUpwardSteps }: { maxUpwardSteps: number }) => {
  const ourScriptUrl = import.meta.url;
  const ourScriptPath = nodeUrl.fileURLToPath(ourScriptUrl);
  const ourScriptDirectory = nodePath.dirname(ourScriptPath);

  const ourPackageJsonPath = findPackageJson({
    startPath: ourScriptDirectory,
    maxUpwardSteps,
  });

  const ourPackageRoot = nodePath.dirname(ourPackageJsonPath);

  return ourPackageRoot;
};

const findAddonInAddonFolder = ({ addonFolderPath }: { addonFolderPath: string }) => {
  const entries = nodeFs.readdirSync(addonFolderPath);

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

const loadAddonAtPath = ({ addonFilePath }: { addonFilePath: string }) => {
  const require = nodeModule.createRequire(import.meta.url);

  const native = require(addonFilePath);

  return native;
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

  const debugFolderExists = nodeFs.existsSync(debugFolderPath);
  const releaseFolderExists = nodeFs.existsSync(releaseFolderPath);

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

  const native = loadAddonAtPath({ addonFilePath });

  return native;
};

const createNativeAddonLoader = () => {

  const loadRelativeToPackageRoot = ({ relativeBuildFolderPath }: { relativeBuildFolderPath: string }) => {
    let packageRoot: string;

    try {
      packageRoot = findPackageRoot({ maxUpwardSteps: 10 });
    } catch (err) {
      let message = "could not find our package root";
      message += ", make sure to keep the package structure intact when distributing the package";
      message += " - a package.json and built addon at ./build are required";
      throw Error(message, { cause: err });
    }

    const buildFolderPath = nodePath.join(packageRoot, relativeBuildFolderPath);

    if (!nodeFs.existsSync(buildFolderPath)) {
      throw Error(`no build folder found at our package root "${buildFolderPath}", make sure to build the native addon first`);
    }

    const addonFolderPath = determineReleaseOrDebugFolder({ buildFolderPath });
    const native = loadAddonFromFolder({ addonFolderPath });

    return native;
  };

  return {
    loadRelativeToPackageRoot,
  };
};

export {
  createNativeAddonLoader,
};
