#ifndef __OPENSSL_SERVERLIB_H__
#define __OPENSSL_SERVERLIB_H__

#include <openssl/ssl.h>
#include <openssl/srp.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdbool.h>
#include <assert.h>

#include <signal.h>
#include <pthread.h>

#include <sys/select.h>
#include <sys/types.h>

#define CERT_FILE "cert.pem"
#define PRIVKEY_FILE "privkey.pem"
#define BUFLEN 4096
#define SSL_OK 1

#define USERNAME "vasudev"
#define PASSWORD "kamath"
#define SRPGROUP "1536"

#define CHECK(e) ((e) ? (void)(0): onError(#e, __FILE__, __LINE__, true))

typedef struct {
  SSL_CTX *ctx;
  BIO *bio;
  int client_number;
} SSLThreadDataT;

extern volatile bool terminated;
static SRP_VBASE *srpData;

pthread_mutex_t srpDataMutex;

void initOpenSSL();
void sslCleanup();

int sslWait(SSL*, int);
int sslHandShake(SSL *);

void setupSSLCerts(SSL_CTX *);

int sslHandleMessage(SSL*);
int SSL_echo_content(SSL *, const char *, int );

void onError(const char*, const char*, int, bool);

void sigint_handler(int);
void setsighandler();

/* SRP related functions */
void setupSrpData();
int srpCallback(SSL*,int *, void*);
#endif
