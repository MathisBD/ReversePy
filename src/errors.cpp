#include "errors.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void pAssert(bool cond)
{
    if (!cond) {
        panic("assertion failed\n");
    }
}

void panic(const char* msg, ...)
{
    va_list args;
    va_start(args, msg);

    FILE* errorFile = fopen("output/errors", "w");
    vfprintf(errorFile, msg, args);
    fclose(errorFile);
    
    va_end(args);
    exit(EXIT_FAILURE);
}