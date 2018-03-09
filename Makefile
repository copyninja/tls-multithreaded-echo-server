SRC = $(wildcard src/*.c)
SSL ?= none

ifneq (, $(findstring none, $(SSL)))
filter_files = src/openssl_serverlib.c src/openssl_x509.c
LIBS = -lpthread
SRCS = $(filter-out $(filter_files), $(SRC))
endif

ifneq (, $(findstring openssl, $(SSL)))
filter_files = src/server.c
LIBS = -lssl -lcrypto -lpthread
SRCS = $(filter-out $(filter_files), $(SRC))
endif

ifneq (, $(findstring srp, $(SSL)))
filter_files = src/server.c src/openssl_x509.c
LIBS = -lssl -lcrypto -lpthread
SRCS = $(filter-out $(filter_files), $(SRC))
endif

OBJS = $(patsubst %/*.o, *.o, $(SRCS:.c=.o))
CCFLAGS = -Wall -ggdb

BINARY=thread_server

%.o: %.c
	$(CC) $(CFLAGS) $(CCFLAGS) -c $< -o $@

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $(BINARY) $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) $(BINARY)

%.pem:
	openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out cert.pem -days 365 -nodes
