#include "logger.h"

LOG_LEVEL current_level = DEBUG;

FILE *log_file = NULL;

void setLogLevel(LOG_LEVEL newLevel) {
	if ( newLevel >= DEBUG && newLevel <= FATAL )
	   current_level = newLevel;
}

char * levelDescription(LOG_LEVEL level) {
    static char *description[] = {
        "\033[0;36mDEBUG\033[0m",  // Cian
        "\033[0;32mINFO\033[0m",   // Verde
        "\033[0;31mERROR\033[0m",  // Amarillo
        "\033[0;31mFATAL\033[0m"   // Rojo
    };
    if (level < DEBUG || level > FATAL)
        return "";
    return description[level];
}

char * levelDescriptionPlain(LOG_LEVEL level) {
    static char *description[] = {
        "DEBUG",
        "INFO",
        "ERROR",
        "FATAL"
    };
    if (level < DEBUG || level > FATAL)
        return "";
    return description[level];
}

void setLogFile(const char *filename) {
    if (log_file != NULL && log_file != stderr) {
        fclose(log_file);
    }
    log_file = fopen(filename, "a");
    if (log_file == NULL) {
        log_file = stderr;
    }
}
