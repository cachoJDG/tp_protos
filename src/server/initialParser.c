#include "../shared/util.h"
#include "initialParser.h"

// -------- internal --------

parser_ret ini_version_countmethods(struct buffer *buffer, socks5_initial_parserinfo* parserInfo) {
    parserInfo->socksVersion = buffer_read(buffer);
    parserInfo->methodCount = buffer_read(buffer);
    parserInfo->substate = 1;
    parserInfo->toRead = parserInfo->methodCount;
    return PARSER_INCOMPLETE; // Need to read methods next
}

parser_ret ini_methods(struct buffer *buffer, socks5_initial_parserinfo* parserInfo) {
    buffer_read_bytes(buffer, (uint8_t *)parserInfo->authMethods, parserInfo->methodCount);
    return PARSER_OK;
}

parser_ret (* initialParserSubstates[])(struct buffer *buffer, socks5_initial_parserinfo* parserInfo) = {
    ini_version_countmethods, // 0
    ini_methods // 1
};

// -------- public API --------

void ini_initialize(socks5_initial_parserinfo* parserInfo) {
    parserInfo->substate = 0;
    parserInfo->toRead = 2; // Initial bytes to read for version and method count
}

parser_ret ini_parse(struct buffer *buffer, socks5_initial_parserinfo* parserInfo, ssize_t bytesRead) {
    parserInfo->toRead -= bytesRead;
    if (parserInfo->toRead > 0) {
        return PARSER_INCOMPLETE; // Not enough bytes read yet
    }
    if (parserInfo->toRead < 0) {
        log(FATAL, "Received more bytes than expected in initial read. FIX NEEDED");
        return PARSER_ERROR; // More bytes read than expected
    }

    // Call the appropriate substate parser
    return initialParserSubstates[parserInfo->substate](buffer, parserInfo);
}
