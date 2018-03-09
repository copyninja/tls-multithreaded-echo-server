# About #

This is the effort similar to
[tls-echo-server](https://github.com/copyninja/tls-echo-server) repository, now
idea is to implement the code using POSIX threads instead of old fork based
model.

  * server.c - Is the implementation without SSL using just pthreads.
  * openssl_x509.c - Is the implementation using x509 certificate and OpenSSL
    library.
  * openssl_srp.c - Is the implementation using TLS-SRP using OpenSSL library.

# Compiling #

Most of the compilation remains similar to
[tls-echo-server](https://github.com/copyninja/tls-echo-server) repository. Only
here I've dropped GnuTLS implementation and `SSL` compile time argument to make
now takes one of the `none` `openssl` `srp` as arguments.

# Improvements #
  * Unlike previous code now number of clients can be controlled by varying the
    value of `MAX_CLIENTS` C-preprocessor macro.

If you have improvements or suggestions please feel free to provide those via PR.
