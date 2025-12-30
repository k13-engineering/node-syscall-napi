import sys from "../lib/index.ts";

process.nextTick(async () => {
  try {
    const pid = sys.syscall(sys.__NR_getpid);
    console.log(`pid = ${pid}`);
  } catch (ex) {
    console.error(ex);
    process.exitCode = -1;
  }
});
