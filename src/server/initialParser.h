#ifndef INITIAL_PARSER_H
#define INITIAL_PARSER_H

#include "../buffer.h"
#include "../shared/util.h"

typedef enum parser_ret {
    PARSER_OK,
    PARSER_ERROR,
    PARSER_INCOMPLETE
} parser_ret;

void ini_initialize(socks5_initial_parserinfo* parserInfo);
parser_ret ini_parse(struct buffer *buffer, socks5_initial_parserinfo* parserInfo, ssize_t bytesRead);

#endif // INITIAL_PARSER_H