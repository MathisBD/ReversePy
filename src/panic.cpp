#include "panic.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

extern FILE* errorFile;
void panic(const char* msg, ...)
{
    va_list argList;
    va_start(argList, msg);
    vfprintf(errorFile, msg, argList);
    va_end(argList);

    fprintf(errorFile, "ABNORMAL EXIT\n");
    exit(EXIT_FAILURE);
}