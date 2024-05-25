#ifndef TLS_CONNECTION_INCLUDED
#define TLS_CONNECTION_INCLUDED

#include <sys/types.h>
#include <netinet/in.h>

struct tls_connection;

struct tls_connection_ops {
    ssize_t(*write) (struct tls_connection *, const void *, size_t);
    ssize_t(*read) (struct tls_connection *, void *, size_t);
    int (*close)(struct tls_connection *);
};

struct tls_connection {
    const struct tls_connection_ops *ops;
};

struct tls_connection *tls_connect(const struct sockaddr_in *);
ssize_t tls_connection_write(struct tls_connection *, const void *,
			     size_t);
ssize_t tls_connection_read(struct tls_connection *, void *, size_t);
int tls_connection_close(struct tls_connection *);

#endif
