SRC = $(wildcard src/*.c)
OBJS = $(patsubst %/*.o, *.o, $(SRC:.c=.o))

CCFLAGS = -Wall -ggdb
LIBS = -lpthread

BINARY=thread_server

%.o: %.c
	$(CC) $(CFLAGS) $(CCFLAGS) -c $< -o $@

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $(BINARY) $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) $(BINARY)
