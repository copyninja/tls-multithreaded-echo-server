#include "openssl_serverlib.h"
#include "server_lib.h"

void *processConnectionRequest(void *data) {
  pthread_detach(pthread_self());

  SSLThreadDataT *t = (SSLThreadDataT*)data;

  SSL *ssl = SSL_new(t->ctx);
  CHECK(ssl != NULL);
  SSL_set_bio(ssl, t->bio, t->bio);

  while(true) {
    int res = sslHandShake(ssl);
    if (res > 0)
      break;
    else {
      fprintf(stderr, "Failed to do the handshake: %d\n", res);
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      pthread_exit(NULL);
    }
  }

  while (!terminated) {
    int rv = sslHandleMessage(ssl);
    if (rv < 0) {
      if (rv != SSL_ERROR_ZERO_RETURN)
        SSL_shutdown(ssl);
      clientDone();
      printf("Client: %d disconnected!\n", t->client_number);
      break;
    }
  }

  SSL_free(ssl);
  free(t);
  pthread_exit(NULL);
}

void gracefullyRefuse(SSL_CTX *ctx, BIO *bio) {
  SSL *ssl = SSL_new(ctx);
  SSL_set_bio(ssl, bio, bio);

  while (true) {
    int res = sslHandShake(ssl);
    if (res > 0)
      break;
    else {
      fprintf(stderr, "Failed ssl hand shake: %d\n", res);
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      return;
    }
  }

  SSL_write(ssl, "Maximum clients connected! Refusing more connection...\n", 56);
  SSL_shutdown(ssl);
  SSL_free(ssl);
}

int main(int argc, char *argv[]) {
  initOpenSSL();

  pthread_t clients[MAX_CLIENT];
  char buf[80] = {'\0'};

  const SSL_METHOD *method = SSLv23_server_method();

  SSL_CTX *ctx = SSL_CTX_new(method);
  CHECK(ctx != NULL);

  setupSSLCerts(ctx);

  /* Prepare BIO for server  connection acceptance */
  BIO *server = BIO_new_accept("50000");
  CHECK(server != NULL);
  CHECK(BIO_set_bind_mode(server, BIO_BIND_REUSEADDR) == SSL_OK);
  BIO_set_nbio(server, 1);

  setsighandler();

  int ret = BIO_do_accept(server);
  if (ret <= 0) {
    fprintf(stderr, "BIO_do_accept failed: %d\n", ret);
  } else {
    while(!terminated) {
      if (BIO_do_accept(server) <= 0) {
        if (errno != EINTR) {
          fprintf(stderr, "accept failed \n");
          ERR_print_errors_fp(stderr);
        }
        break;
      }

      int client_number = clientAccept();
      BIO *bio = BIO_pop(server);
      CHECK(bio != NULL);

      int fd = BIO_get_fd(bio, NULL);
      struct sockaddr_in addr;
      int addrlen = sizeof(addr);
      if (getpeername(fd, (struct sockaddr*)&addr, (socklen_t*)&addrlen) < 0)
        printf("Failed to deduce connected client address client: %d\n", client_data.client_number);
      else
        printf("- connection accpeted from %s port %d client: %d\n",
               inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf)),
               addr.sin_port,
             client_number);
      if (client_number <= MAX_CLIENT) {
        SSLThreadDataT *st = (SSLThreadDataT *)malloc(sizeof(SSLThreadDataT));
        CHECK(st != NULL);
        st->ctx = ctx;
        st->bio = bio;
        st->client_number = client_data.client_number;
        if (pthread_create(&clients[client_number], NULL,
                           processConnectionRequest, (void *)st) != 0) {
          fprintf(stderr, "Failed to create thread!\n");
          goto cleanup;
        }

      } else {
        gracefullyRefuse(ctx, bio);
        clientDone();
      }
    }
  }

 cleanup:
  BIO_free(server);
  SSL_CTX_free(ctx);
  sslCleanup();
}
