import sys from "../lib/index.js";

process.nextTick(async () => {
  try {
    const pid = await sys.syscall(sys.__NR_getpid);
    console.log(`pid = ${pid}`);
  } catch (ex) {
    console.error(ex);
    process.exitCode = -1;
  }
});
