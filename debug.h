
#ifndef INCLUDE_DEBUG_H
#define INCLUDE_DEBUG_H


// Define priority levels
typedef enum {
    LOG_LEVEL_OFF,    // No debug messages
    LOG_LEVEL_ERROR,  // Error messages only
    LOG_LEVEL_WARN,   // Warning and error messages
    LOG_LEVEL_INFO,   // Information, warning, and error messages
    LOG_LEVEL_DEBUG   // All messages (debug, information, warning, and error)
} DebugLevel;

// Global variable to store the current debug threshold
static DebugLevel debugLevel = LOG_LEVEL_DEBUG;


// Function to print a debug message
void debugPrint(DebugLevel level, const char* format, ...);

#define INSPECTOR_PLUGIN_DEBUG(...) debugPrint(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define INSPECTOR_PLUGIN_INFO(...)  debugPrint(LOG_LEVEL_INFO, __VA_ARGS__)
#define INSPECTOR_PLUGIN_WARN(...)  debugPrint(LOG_LEVEL_WARN, __VA_ARGS__)
#define INSPECTOR_PLUGIN_ERROR(...) debugPrint(LOG_LEVEL_ERROR, __VA_ARGS__)

#endif //INCLUDE_DEBUG_H
