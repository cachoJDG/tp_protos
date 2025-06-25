include ./Makefile.inc

MONITORING_SOURCES=$(wildcard src/monitoring/*.c) src/selector.c src/stm.c
MONITORING_OBJECTS=$(MONITORING_SOURCES:src/%.c=obj/%.o)

SERVER_SOURCES=$(wildcard src/*.c src/server/*.c)
SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)

CLIENT_SOURCES=$(wildcard src/client/*.c)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)

SHARED_SOURCES=$(wildcard src/shared/*.c)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)

USERS_SOURCES=$(wildcard src/users/*.c)
USERS_OBJECTS=$(USERS_SOURCES:src/%.c=obj/%.o)

OUTPUT_FOLDER=./bin
OBJECTS_FOLDER=./obj

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/socks5v
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client
MONITORING_OUTPUT_FILE=$(OUTPUT_FOLDER)/monitoring

all: server client monitoring

server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)
monitoring: $(MONITORING_OUTPUT_FILE)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_OUTPUT_FILE)

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) $(CLIENT_OBJECTS) $(SHARED_OBJECTS) -o $(CLIENT_OUTPUT_FILE)

$(MONITORING_OUTPUT_FILE): $(MONITORING_OBJECTS) $(SHARED_OBJECTS) $(USERS_OBJECTS)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) $(MONITORING_OBJECTS) $(SHARED_OBJECTS) $(USERS_OBJECTS) -o $(MONITORING_OUTPUT_FILE)

obj/%.o: src/%.c
	mkdir -p $(@D)
	$(CC) $(GCCFLAGS) -c $< -o $@


clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

check:
	mkdir -p check
	cppcheck --quiet --enable=all --force --inconclusive . 2> ./check/cppout.txt

	pvs-studio-analyzer trace -- make
	pvs-studio-analyzer analyze
	plog-converter -a '64:1,2,3;GA:1,2,3;OP:1,2,3' -t tasklist -o ./check/report.tasks ./PVS-Studio.log

	rm PVS-Studio.log
	mv strace_out check

.PHONY: all server client clean check