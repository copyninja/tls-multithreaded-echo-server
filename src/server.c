#include "server_lib.h"

#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>
#include <errno.h>


int main(int argc, char *argv[]) {
  Server s = setup_socket();
  pthread_t clients[MAX_CLIENT];

  int connfd;

  client_data.client_number = 0;
  pthread_mutex_init(&clientMutex, NULL);

  char buf[33] = {'\0'};

  for(;;) {
    connfd = accept(s.sockfd, (struct sockaddr*)&s.sa, (socklen_t*)&s.addrlen);

    if (connfd < 0 && errno != EAGAIN)
      handle_error("accept failed");

    if (connfd > 0) {
      int client_number = clientAccept();
      printf("- connection accepted from %s port %d client: %d\n",
             inet_ntop(AF_INET, &s.sa.sin_addr, buf, sizeof(buf)),
             s.sa.sin_port, client_number);
      if (client_data.client_number <= MAX_CLIENT) {
        socket_nonblocking(&connfd);
        disable_nagles_algo(&connfd);

        /* Send the client number to client first */
        send(connfd, (void *)&client_number,
                  sizeof(client_number), 0);

        ThreadDataT *t = (ThreadDataT*)malloc(sizeof(ThreadDataT));
        t->fd = connfd;
        t->number = client_number;
        t->sa = s.sa;

        if (pthread_create(&clients[client_number-1], NULL, HandleMessage, (void*)t) != 0){
          handle_error("pthread_create failed");
        }
      }
        else {
          send(connfd, "Max clients reached!\n", 21, 0);
          clientDone();
          close(connfd);
        }
    }

  }

  close(s.sockfd);
}
