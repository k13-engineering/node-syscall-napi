#include <asm/unistd.h>

#include <stdio.h>

static void print_sys_constant(const char* name, int value) {
  char name_without_prefix[256];
  snprintf(name_without_prefix, sizeof(name_without_prefix), "%s", name + 5); // Skip "__NR_"
  printf("  %s: %dn,\n", name_without_prefix, value);
}

#define PRINT_SYS_CONSTANT(name) print_sys_constant(#name, name)

int main(int argc, char* argv[]) {
  printf("const syscallNumbers = {\n");
  #include "print-statements.c"
  printf("};\n");
  printf("\n");
  printf("export {\n");
  printf("  syscallNumbers\n");
  printf("};\n");

  return 0;
}
