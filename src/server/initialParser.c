#include "../shared/util.h"
#include "initialParser.h"
#include "../shared/logger.h"

// -------- internal --------

parser_ret ini_version_countmethods(struct buffer *buffer, socks5_initial_parserinfo* parserInfo, ssize_t *toRead) {
    parserInfo->socksVersion = buffer_read(buffer);
    parserInfo->methodCount = buffer_read(buffer);
    parserInfo->substate = 1;
    *toRead = parserInfo->methodCount;
    if(parserInfo->methodCount == 0) {
        return PARSER_OK; // No methods to read
    }
    log(DEBUG, "socksVersion=%d, methodCount=%d", parserInfo->socksVersion, parserInfo->methodCount);
    return PARSER_INCOMPLETE; // Need to read methods next
}

parser_ret ini_methods(struct buffer *buffer, socks5_initial_parserinfo* parserInfo, ssize_t *toRead) {
    buffer_read_bytes(buffer, (uint8_t *)parserInfo->authMethods, parserInfo->methodCount);
    *toRead = 0; // No more bytes to read
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
        log(FATAL, "Received more bytes than expected in initial read. FIX NEEDED %ld", *toRead);
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
        // log(DEBUG, "No password provided, skipping password parsing");
        return PARSER_OK;
    }
    parserInfo->substate = 2; // Move to next substate
    return PARSER_INCOMPLETE;
}

parser_ret login_pass(struct buffer *buffer, socks5_login_parserinfo* parserInfo, ssize_t *toRead) {
    buffer_read_bytes(buffer, (uint8_t *)parserInfo->password, parserInfo->passwordLength);
    *toRead = 0; // No more bytes to read
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
        log(FATAL, "Received more bytes than expected in login read. FIX NEEDED %ld", *toRead);
        return PARSER_ERROR; // More bytes read than expected
    }
    // log(DEBUG, "login_parse: substate=%d, toRead=%zd", parserInfo->substate, *toRead);

    // Call the appropriate substate parser
    return loginParserSubstates[parserInfo->substate](buffer, parserInfo, toRead);
}


// -------- request parser --------
// -------- internal --------

typedef enum AddressTypeSocksv5 {
    SOCKSV5_ADDR_TYPE_IPV4 = 0x01,
    SOCKSV5_ADDR_TYPE_DOMAIN_NAME = 0x03,
    SOCKSV5_ADDR_TYPE_IPV6 = 0x04
} AddressTypeSocksv5;

void logParserInfo(socks5_request_parserinfo* parserInfo) {
    log(DEBUG, "socksVersion=%d, command=%d, reserved=%d, addressType=%d",
        parserInfo->socksVersion,
        parserInfo->command,
        parserInfo->reserved,
        parserInfo->addressType
    );
}

parser_ret req_command_addrtype(struct buffer *buffer, socks5_request_parserinfo* parserInfo, ssize_t *toRead) {
    parserInfo->socksVersion = buffer_read(buffer);
    parserInfo->command = buffer_read(buffer);
    parserInfo->reserved = buffer_read(buffer); // Reserved byte, should be 0x00
    parserInfo->addressType = buffer_read(buffer);
    // logParserInfo(parserInfo);
    switch(parserInfo->addressType) {
        case SOCKSV5_ADDR_TYPE_IPV4:
            *toRead = sizeof(uint32_t); // IPv4 address (4 bytes)
            parserInfo->substate = 1;
            break;
        case SOCKSV5_ADDR_TYPE_DOMAIN_NAME:
            *toRead = 1; // Domain name length byte
            parserInfo->substate = 2;
            break;
        case SOCKSV5_ADDR_TYPE_IPV6:
            *toRead = 16; // IPv6 address (16 bytes)
            parserInfo->substate = 4;
            break;
        default:
            log(DEBUG, "Invalid address type %d", parserInfo->addressType);
            *toRead = 0;
            return PARSER_OK; // Invalid address type
    }
    return PARSER_INCOMPLETE;
}

parser_ret req_ipv4(struct buffer *buffer, socks5_request_parserinfo* parserInfo, ssize_t *toRead) {
    struct in_addr rawAddress;
    buffer_read_bytes(buffer, (uint8_t*)&rawAddress, sizeof(rawAddress));
    // parserInfo->ipv4 = ntohl(rawAddress);
    parserInfo->ipv4 = rawAddress; // Store the raw address directly
    *toRead = sizeof(uint16_t); // Port (2 bytes)
    parserInfo->substate = 5;
    return PARSER_INCOMPLETE;
}

parser_ret req_domainlength(struct buffer *buffer, socks5_request_parserinfo* parserInfo, ssize_t *toRead) {
    parserInfo->domainNameLength = buffer_read(buffer);
    *toRead = parserInfo->domainNameLength; // Domain name
    if (parserInfo->domainNameLength == 0) {
        // log(ERROR, "Domain name length is ");
        return PARSER_ERROR; // Invalid domain name length
    }
    *toRead = parserInfo->domainNameLength;
    parserInfo->substate = 3;
    return PARSER_INCOMPLETE;
}

parser_ret req_domainname(struct buffer *buffer, socks5_request_parserinfo* parserInfo, ssize_t *toRead) {
    buffer_read_bytes(buffer, (uint8_t *)parserInfo->domainName, parserInfo->domainNameLength);
    parserInfo->domainName[parserInfo->domainNameLength] = '\0'; // Null-terminate the string
    *toRead = sizeof(uint16_t); // Port (2 bytes)
    parserInfo->substate = 5;
    return PARSER_INCOMPLETE;
}

parser_ret req_ipv6(struct buffer *buffer, socks5_request_parserinfo* parserInfo, ssize_t *toRead) {
    buffer_read_bytes(buffer, (uint8_t *)&parserInfo->ipv6, sizeof(parserInfo->ipv6));
    *toRead = sizeof(uint16_t); // Port (2 bytes)
    parserInfo->substate = 5;
    return PARSER_INCOMPLETE;
}

parser_ret req_port(struct buffer *buffer, socks5_request_parserinfo* parserInfo, ssize_t *toRead) {
    uint16_t rawPort;
    buffer_read_bytes(buffer, (uint8_t *)&rawPort, sizeof(rawPort));
    parserInfo->port = ntohs(rawPort);  // Convert from network to host byte order
    *toRead = 0; // No more bytes to read
    // logParserInfo(parserInfo);
    return PARSER_OK;  // Parsing complete
}

parser_ret (* requestParserSubstates[])(struct buffer *buffer, socks5_request_parserinfo* parserInfo, ssize_t *toRead) = {
    req_command_addrtype, // 0
    req_ipv4,             // 1
    req_domainlength,     // 2
    req_domainname,       // 3
    req_ipv6,             // 4
    req_port              // 5
};

// -------- public API --------

void request_initialize(socks5_request_parserinfo* parserInfo, ssize_t *toRead) {
    parserInfo->substate = 0;
    *toRead = 4; // Initial bytes to read for command, reserved byte, and address type
}

parser_ret request_parse(struct buffer *buffer, socks5_request_parserinfo* parserInfo, ssize_t *toRead) {
    if (*toRead > 0) {
        return PARSER_INCOMPLETE; // Not enough bytes read yet
    }
    if (*toRead < 0) {
        log(FATAL, "Received more bytes than expected in request read. FIX NEEDED %ld", *toRead);
        return PARSER_ERROR; // More bytes read than expected
    }
    // log(DEBUG, "request_parse: substate=%d, toRead=%zd", parserInfo->substate, *toRead);

    // Call the appropriate substate parser
    return requestParserSubstates[parserInfo->substate](buffer, parserInfo, toRead);
}



