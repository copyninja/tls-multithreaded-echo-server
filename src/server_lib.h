#ifndef __SERVER_LIB_H__
#define __SERVER_LIB_H__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while(0)

#define PORT 50000
#define MAX_CLIENT 2

typedef struct {
  int sockfd;
  struct sockaddr_in sa;
  int addrlen;
} Server;

typedef unsigned char ClientNumber;

typedef struct {
  ClientNumber clients[MAX_CLIENT];
  short client_number;
} ClientDataT;

ClientDataT client_data;
pthread_mutex_t clientMutex;

typedef struct {
  int fd;
  int number;
  struct sockaddr_in sa;
} ThreadDataT;

Server setup_socket(void);
int echo_content(int *);
void socket_nonblocking(int *);
void disable_nagles_algo(int *);
void* HandleMessage(void*);

int clientAccept();
void clientDone();


#endif /* __SERVER_LIB_H__ */
