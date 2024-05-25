#include "tls_connection.h"
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>

struct tls_connection_impl {
    struct tls_connection super;
    int sockfd;
};

static ssize_t tls_read(struct tls_connection *conn, void *buf,
			size_t count)
{
    return read(((struct tls_connection_impl *) conn)->sockfd, buf, count);
}

static ssize_t tls_write(struct tls_connection *conn, const void *buf,
			 size_t count)
{
    return write(((struct tls_connection_impl *) conn)->sockfd, buf,
		 count);
}

static int tls_close(struct tls_connection *conn)
{
    int ret = close(((struct tls_connection_impl *) conn)->sockfd);
    if (ret != 0)
	return ret;
    free(conn);
    return ret;
}


static struct tls_connection_ops tls_connection_vtable = {
    .write = tls_write,
    .read = tls_read,
    .close = tls_close,
};

struct tls_connection *tls_connect(const struct sockaddr_in *addr)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
	return NULL;

    if (connect
	(sockfd, (const struct sockaddr *) addr,
	 sizeof(struct sockaddr_in)) < 0) {
	close(sockfd);
	return NULL;
    }

    struct tls_connection_impl *conn =
	malloc(sizeof(struct tls_connection_impl));
    if (conn == NULL) {
	close(sockfd);
	return NULL;
    }

    conn->super.ops = &tls_connection_vtable;
    conn->sockfd = sockfd;
    return (struct tls_connection *) conn;
}

ssize_t tls_connection_write(struct tls_connection *conn, const void *buf,
			     size_t count)
{
    ssize_t written;
    size_t left = count;

    while (left > 0) {
	written = conn->ops->write(conn, buf, left);
	if (written <= 0) {
	    if (written < 0 && errno == EINTR)
		continue;
	    else
		return -1;
	}
	left -= written;
	buf += written;
    }

    return count;
}

ssize_t tls_connection_read(struct tls_connection *conn, void *buf,
			    size_t count)
{
    ssize_t read;
    size_t left = count;

    while (left > 0) {
	read = conn->ops->read(conn, buf, left);
	if (read <= 0) {
	    if (read < 0 && errno == EINTR)
		continue;
	    else
		return -1;
	}
	left -= read;
	buf += read;
    }

    return count;
}

int tls_connection_close(struct tls_connection *conn)
{
    return conn->ops->close(conn);
}
