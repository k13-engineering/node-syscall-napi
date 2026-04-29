{
  "targets": [
    {
      "target_name": "syscall",
      "sources": [ "native/syscall.c" ],
      "cflags": [ "-nostdlib", "-nodefaultlibs", "-ffreestanding" ],
      "ldflags": [ "-nostdlib", "-nodefaultlibs" ],
      "libraries": []
    }
  ]
}
