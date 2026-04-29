import nodeFs from "node:fs";

const fdToProcfsPath = ({ fd }: { fd: number }) => {
  return `/proc/self/fd/${fd}`;
};

// eslint-disable-next-line no-underscore-dangle
const __O_TMPFILE = 0o20000000;
const O_TMPFILE = __O_TMPFILE | nodeFs.constants.O_DIRECTORY;

const binaryToFd = ({ binary }: { binary: Uint8Array }) => {
  const writeFd = nodeFs.openSync("/tmp", O_TMPFILE | nodeFs.constants.O_RDWR, 0o700);
  nodeFs.writeSync(writeFd, binary);

  const readOnlyFdPath = fdToProcfsPath({ fd: writeFd });
  const fd = nodeFs.openSync(readOnlyFdPath, nodeFs.constants.O_RDONLY);
  nodeFs.closeSync(writeFd);

  return {
    fd
  };
};

export {
  binaryToFd,
  fdToProcfsPath
};
