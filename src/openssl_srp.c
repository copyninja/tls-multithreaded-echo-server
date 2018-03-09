#include "openssl_serverlib.h"
#include "server_lib.h"

void *processConnectionRequest(void *data) {
  pthread_detach(pthread_self());

  SSLThreadDataT *t = (SSLThreadDataT *)data;

  if (BIO_do_handshake(t->bio) <= 0) {
    fprintf(stderr, "Eror in SSL handshake\n");
    ERR_print_errors_fp(stderr);
    clientDone();
    free(t);
    pthread_exit(NULL);
  }

  SSL *ssl;
  BIO_get_ssl(t->bio, &ssl);

  /* TODO: cleanly exit here */
  CHECK(ssl != NULL);

  while (!terminated) {
    int rv = sslHandleMessage(ssl);
    if (rv < 0) {
      clientDone();
      if (rv != SSL_ERROR_ZERO_RETURN)
        SSL_shutdown(ssl);
      printf("Client: %d is disconnected\n", t->client_number);
      break;
    }
  }

  int fd = BIO_get_fd(t->bio, NULL);
  close(fd);
  BIO_free(t->bio);
  free(t);
  pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
  pthread_mutex_init(&srpDataMutex, NULL);
  initOpenSSL();

  const SSL_METHOD *method = SSLv23_server_method();
  CHECK(method != NULL);

  SSL_CTX *ctx = SSL_CTX_new(method);
  CHECK(ctx != NULL);

  CHECK(SSL_CTX_set_srp_username_callback(ctx, srpCallback) == SSL_OK);
  setupSrpData();

  char buf[81] = {'\0'};
  pthread_t clients[MAX_CLIENT];

  BIO *sbio, *bbio, *server;
  sbio = BIO_new_ssl(ctx, 0);

  bbio = BIO_new(BIO_f_buffer());
  sbio = BIO_push(bbio, sbio);

  server = BIO_new_accept("50000");
  BIO_set_accept_bios(server, sbio);

  setsighandler();

  int ret = BIO_do_accept(server);
  if (ret <= 0) {
    fprintf(stderr, "BIO_do_accept failed: %d\n", ret);
  } else {
    while (!terminated) {
      if (BIO_do_accept(server) <= 0) {
        if (errno != EINTR) {
          fprintf(stderr, "Failed to accept \n");
          ERR_print_errors_fp(stderr);
        }
        break;
      }

      int client_number = clientAccept();
      sbio = BIO_pop(server);

      int fd = BIO_get_fd(sbio, NULL);
      struct sockaddr_in addr;
      int addrlen = sizeof(addr);
      if (getpeername(fd, (struct sockaddr *)&addr, (socklen_t *)&addrlen) <
          0) {
        printf("- WARNING: Failed to get the address of client: %d\n",
               client_number);
      } else {
        printf("- connection accepted from %s port %d client: %d\n",
               inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf)),
               addr.sin_port, client_number);
      }

      if (client_number <= MAX_CLIENT) {
        SSLThreadDataT *t = (SSLThreadDataT *)malloc(sizeof(SSLThreadDataT));
        t->ctx = ctx;
        t->bio = sbio;
        t->client_number = client_number;
        if (pthread_create(&clients[client_number - 1], NULL,
                           processConnectionRequest, (void *)t) != 0) {
          fprintf(stderr, "Failed to create thread");
          goto cleanup;
        }
      }
    }
  }

cleanup:
  if (srpData != NULL)
    SRP_VBASE_free(srpData);
  BIO_free_all(server);
  SSL_CTX_free(ctx);
  sslCleanup();
}
