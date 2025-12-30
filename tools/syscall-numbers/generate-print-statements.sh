#!/bin/sh

grep "#define __NR_" /usr/include/asm-generic/unistd.h | awk '{
    name = $2;
    print "#ifdef " name;
    print "PRINT_SYS_CONSTANT(" name ");";
    print "#endif";
}' > print-statements.c
