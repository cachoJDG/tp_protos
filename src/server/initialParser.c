#include "../shared/util.h"
#include "initialParser.h"
#include "../shared/logger.h"

// -------- internal --------

parser_ret ini_version_countmethods(struct buffer *buffer, socks5_initial_parserinfo* parserInfo, ssize_t *toRead) {
    parserInfo->socksVersion = buffer_read(buffer);
    parserInfo->methodCount = buffer_read(buffer);
    parserInfo->substate = 1;
    *toRead = parserInfo->methodCount;
    return PARSER_INCOMPLETE; // Need to read methods next
}

parser_ret ini_methods(struct buffer *buffer, socks5_initial_parserinfo* parserInfo, ssize_t *toRead) {
    buffer_read_bytes(buffer, (uint8_t *)parserInfo->authMethods, parserInfo->methodCount);
    return PARSER_OK;
}

parser_ret (* initialParserSubstates[])(struct buffer *buffer, socks5_initial_parserinfo* parserInfo, ssize_t *toRead) = {
    ini_version_countmethods, // 0
    ini_methods // 1
};

// -------- public API --------

void ini_initialize(socks5_initial_parserinfo* parserInfo, ssize_t *toRead) {
    parserInfo->substate = 0;
    *toRead = 2; // Initial bytes to read for version and method count
}

parser_ret ini_parse(struct buffer *buffer, socks5_initial_parserinfo* parserInfo, ssize_t *toRead) {
    // *toRead -= bytesRead;
    if (*toRead > 0) {
        return PARSER_INCOMPLETE; // Not enough bytes read yet
    }
    if (*toRead < 0) {
        log(FATAL, "Received more bytes than expected in initial read. FIX NEEDED");
        return PARSER_ERROR; // More bytes read than expected
    }

    // Call the appropriate substate parser
    return initialParserSubstates[parserInfo->substate](buffer, parserInfo, toRead);
}

// -------- login parser --------
// -------- internal --------

parser_ret login_version_userlength(struct buffer *buffer, socks5_login_parserinfo* parserInfo, ssize_t *toRead) {
    parserInfo->loginVersion = buffer_read(buffer);
    parserInfo->usernameLength = buffer_read(buffer);
    *toRead = parserInfo->usernameLength; // Next we need to read username
    *toRead += 1; // Also need to read password length
    parserInfo->substate = 1; // Move to next substate
    return PARSER_INCOMPLETE;
}

parser_ret login_user_passlength(struct buffer *buffer, socks5_login_parserinfo* parserInfo, ssize_t *toRead) {
    buffer_read_bytes(buffer, (uint8_t *)parserInfo->username, parserInfo->usernameLength);
    parserInfo->passwordLength = buffer_read(buffer);

    *toRead = parserInfo->passwordLength;
    if(parserInfo->passwordLength == 0) {
        log(DEBUG, "No password provided, skipping password parsing");
        return PARSER_OK;
    }
    parserInfo->substate = 2; // Move to next substate
    return PARSER_INCOMPLETE;
}

parser_ret login_pass(struct buffer *buffer, socks5_login_parserinfo* parserInfo, ssize_t *toRead) {
    buffer_read_bytes(buffer, (uint8_t *)parserInfo->password, parserInfo->passwordLength);
    return PARSER_OK; // Finished parsing login data
}

parser_ret (* loginParserSubstates[])(struct buffer *buffer, socks5_login_parserinfo* parserInfo, ssize_t *toRead) = {
    login_version_userlength, // 0
    login_user_passlength,    // 1
    login_pass                // 2
};

// -------- public API --------

void login_initialize(socks5_login_parserinfo* parserInfo, ssize_t *toRead) {
    parserInfo->substate = 0;
    *toRead = 2; // Initial bytes to read for version and username length
}

parser_ret login_parse(struct buffer *buffer, socks5_login_parserinfo* parserInfo, ssize_t *toRead) {
    if (*toRead > 0) {
        return PARSER_INCOMPLETE; // Not enough bytes read yet
    }
    if (*toRead < 0) {
        log(FATAL, "Received more bytes than expected in login read. FIX NEEDED");
        return PARSER_ERROR; // More bytes read than expected
    }
    log(DEBUG, "login_parse: substate=%d, toRead=%zd", parserInfo->substate, *toRead);

    // Call the appropriate substate parser
    return loginParserSubstates[parserInfo->substate](buffer, parserInfo, toRead);
}