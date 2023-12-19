
#include <stdio.h>
#include <stdarg.h>
#include "debug.h"

void debugPrint(DebugLevel level, const char* format, ...) {
    // Check if the priority is above the current threshold
    if (level > debugLevel) {
        return;
    }

    // Print the debug message
    va_list args;
    va_start(args, format);
    
    switch (level) {
        case LOG_LEVEL_ERROR:
            fprintf(stderr, "[ERROR] ");
            break;
        case LOG_LEVEL_WARN:
            fprintf(stderr, "[WARN] ");
            break;
        case LOG_LEVEL_INFO:
            fprintf(stdout, "[INFO] ");
            break;
        case LOG_LEVEL_DEBUG:
            fprintf(stdout, "[DEBUG] ");
            break;
        default:
            break;
    }

    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    va_end(args);
}
