#include "logger.h"

LOG_LEVEL current_level = DEBUG;


void setLogLevel(LOG_LEVEL newLevel) {
	if ( newLevel >= DEBUG && newLevel <= FATAL )
	   current_level = newLevel;
}

char * levelDescription(LOG_LEVEL level) {
    static char * description[] = {"DEBUG", "INFO", "ERROR", "FATAL"};
    if (level < DEBUG || level > FATAL)
        return "";
    return description[level];
}

void print_hex(const unsigned char *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}