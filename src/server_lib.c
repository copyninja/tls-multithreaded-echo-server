#include "server_lib.h"


Server setup_socket(void) {

  int sd, err;
  sd = socket(AF_INET, SOCK_STREAM, 0);

  /* Set socket re-use */
  int flag = 1;
  err = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
  if (err != 0)
    handle_error("setsockopt");

  struct sockaddr_in sa;
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(PORT);
  sa.sin_addr.s_addr = INADDR_ANY;

  if (bind(sd, (struct sockaddr*)&sa, sizeof(sa)) != 0)
    handle_error("bind");

  if (listen(sd, 0) != 0)
    handle_error("listen");

  Server s = {.sockfd = sd, .sa = sa, .addrlen = sizeof(struct sockaddr_in)};

  return s;
}

int echo_content(int *connfd) {
  unsigned char buffer[2048] = {'\0'};
  int size = recv(*connfd, buffer, sizeof(buffer), 0);
  if (size < 0)
    handle_error("recv");

  if (size > 0) {
    if (strstr((const char*)buffer, "quit") != NULL){
      send(*connfd, "bye\n", 4, 0);
      return -10;
    }

    size = send(*connfd, buffer, size, 0);
  } else
    printf("WARNING: Failed to recieve data\n");

  return size;
}

void socket_nonblocking(int *connfd) {
  int options = fcntl(*connfd, F_GETFL, 0);
  if (options < 0)
    handle_error("fcntl");

  options |= O_NONBLOCK;
  if (fcntl(*connfd, F_SETFL, options) < 0)
    handle_error("fnctl");
}

void disable_nagles_algo(int *connfd) {
  int flag = 1;
  if (setsockopt(*connfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int)) < 0)
    handle_error("setsockopt");
}

void* HandleMessage(void *data) {
  /* Lets detach first */
  pthread_detach(pthread_self());

  ThreadDataT *t = (ThreadDataT*)data;
  fd_set testfd;

  char buf[33] = {'\0'};

  FD_ZERO(&testfd);

  int rv = 0;

  for (;;) {
    FD_SET(t->fd, &testfd);
    int result = select(FD_SETSIZE, &testfd, NULL, NULL, NULL);
    if (result < 0) {
      perror("select failed");
      pthread_exit(&result);
    }

    if (result > 0) {
      if(FD_ISSET(t->fd, &testfd)) {
        /* We have some data */
        rv = echo_content(&t->fd);
        if (rv < 0) {
          if (rv != -10)
            perror("echo_content failed");
          printf("Client %d (%s) is done. Closing connection!\n", t->number,
                 inet_ntop(AF_INET, &t->sa.sin_addr, buf, sizeof(buf)));
          close(t->fd);
          free(t);
          clientDone();
          pthread_exit(NULL);
        }
      }
    }
  }

  return 0;
}

void clientDone() {
  if (pthread_mutex_lock(&clientMutex) == 0) {
    client_data.client_number --;
    if (pthread_mutex_unlock(&clientMutex) != 0) {
      fprintf(stderr, "Failed to unlock mutex! Aborting..\n");
      abort();
    }
  }
}
