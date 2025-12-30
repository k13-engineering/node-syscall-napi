#include <asm/unistd.h>

#include <stdio.h>

#define PRINT_SYS_CONSTANT(name) printf("  %s: %in,\n", #name, name)

int main(int argc, char* argv[]) {
  printf("const syscallNumbers = {\n");
  #include "print-statements.c"
  printf("};\n");
  printf("export { syscallNumbers };\n");

  return 0;
}
