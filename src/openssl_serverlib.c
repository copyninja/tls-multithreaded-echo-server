#include "openssl_serverlib.h"

volatile bool terminated = false;

void initOpenSSL() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
}

void sslCleanup() {
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  EVP_cleanup();
}

void setupSSLCerts(SSL_CTX *ctx) {
  CHECK(SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) ==
        SSL_OK);
  CHECK(SSL_CTX_use_PrivateKey_file(ctx, PRIVKEY_FILE, SSL_FILETYPE_PEM) ==
        SSL_OK);
}

void onError(const char *s, const char *file, int line, bool doabort) {
  fprintf(stderr, "'%s' failed: %s:%d\n", s, file, line);
  ERR_print_errors_fp(stderr);
  if (doabort) {
    fprintf(stderr, "Aborting...\n");
    abort();
  }
}

int SSL_echo_content(SSL *ssl, const char *request, int length) {
  char bye[] = "bye\n";
  if (strstr(request, "quit") != NULL) {
    SSL_write(ssl, bye, 4);
    return -10;
  }

  return SSL_write(ssl, request, length);
}

int sslHandleMessage(SSL *ssl) {
  int fd = SSL_get_fd(ssl);
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  int bytes_read = 0;
  bool readBlocked = false;
  int err = 0;
  int result = select(fd + 1, &fds, NULL, NULL, NULL);

  char buf[BUFLEN] = {'\0'};
  if (result < 0)
    return result;
  if (result > 0) {
    if (FD_ISSET(fd, &fds)) {
      do {
        bytes_read = SSL_read(ssl, buf, BUFLEN);
        err = SSL_get_error(ssl, bytes_read);
        switch (err) {
        case SSL_ERROR_NONE:
          result = SSL_echo_content(ssl, buf, bytes_read);
          if (result < 0)
            return result;
          break;
        case SSL_ERROR_ZERO_RETURN:
          /* Connection closed by  */
          return err;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
          readBlocked = true;
          break;
        default:
          return -1;
        }
      } while (SSL_pending(ssl) && !readBlocked);
    }
  }
  return result;
}

int sslWait(SSL *ssl, int res) {
  int err = SSL_get_error(ssl, res);
  bool doread;
  switch (err) {
  case SSL_ERROR_WANT_READ:
    doread = true;
    break;
  case SSL_ERROR_WANT_WRITE:
  case SSL_ERROR_WANT_CONNECT:
    doread = false;
    break;
  default:
    return res;
  }

  int fd = SSL_get_fd(ssl);
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(fd, &fds);
  if (doread)
    res = select(fd + 1, &fds, NULL, NULL, NULL);
  else
    res = select(fd + 1, NULL, &fds, NULL, NULL);
  assert(res == 1);
  assert(FD_ISSET(fd, &fds));
  return SSL_OK;
}

int sslHandShake(SSL *ssl) {
  while (true) {
    int res = SSL_accept(ssl);
    if (res > 0)
      return res;
    else {
      res = sslWait(ssl, res);
      if (res < 0)
        return res;
    }
  }
}

void sigint_handler(int s) {
  printf("Received signal: %d\n", s);
  terminated = true;
}

void setsighandler() {
  struct sigaction sigact;
  memset(&sigact, 0, sizeof(sigact));
  sigact.sa_handler = sigint_handler;
  CHECK(sigaction(SIGINT, &sigact, NULL) == 0);
}
