CFLAGS=-g -fsanitize=address -Wall -Wextra -pedantic -pedantic-errors -std=c11 -D_POSIX_C_SOURCE=200112L -D__BSD_VISIBLE=1 -Wno-unused-parameter -Wno-implicit-fallthrough -O3 

LDFLAGS=-pthread

CFLAGSMAC=-g -Wall -Wextra -pedantic -pedantic-errors -std=c11 -Wno-unused-parameter -Wno-implicit-fallthrough