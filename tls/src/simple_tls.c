#include <openssl/ssl.h>
#include <stdint.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include "tls_connection.h"
#include "tls_impl.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#define DEFAULT_PORT 4433

static struct option cli_options[] = {
    { "port", required_argument, 0, 'p' },
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
};

void print_help(FILE *fp, const char *progname)
{
    size_t len = strlen(progname);
    char path[len + 1];
    strcpy(path, progname);
    fprintf(fp, "Usage: %s [options] <server>\n\n", basename(path));

    fprintf(fp, "-p <port>, --port <port>\n");
    fprintf(fp,
	    "                  The port the server is listening on (default: %u)\n",
	    DEFAULT_PORT);
    fprintf(fp, "-h, --help\n");
    fprintf(fp, "                  Display this help and exit\n");
}



int do_handshake(struct tls_context *ctx)
{
    struct server_hello server_hello;
    struct rsa_premaster_secret premaster;

    rsa_premaster_secret_init(&premaster);

    if (!client_hello_send(ctx)
	|| !server_hello_recv(ctx, &server_hello))
	return 0;

    X509 *server_cert = server_cert_recv(ctx);
    if (!server_cert)
	return 0;

    if (!server_hello_done_recv(ctx)
	|| !key_agreement(ctx, &premaster, server_cert)
	|| !verify_server(ctx)) {
	X509_free(server_cert);
	return 0;
    }

    X509_free(server_cert);
    return 1;
}


int ping_request(struct tls_context *ctx)
{
    uint8_t request[] = "ping";
    struct tls_record record = {
	.type = application_data,
	.version = ctx->version,
	.length = sizeof(request) - 1,
	.fragment = request,
    };

    uint8_t enc_data[tls_context_encrypt(ctx, &record, NULL)];

    if (!tls_context_encrypt(ctx, &record, enc_data))
	return 0;

    record.length = sizeof(enc_data);
    record.fragment = enc_data;

    return tls_context_send_record(ctx, &record, NULL);
}


int ping_reply(struct tls_context *ctx)
{
    struct tls_record record;

    tls_context_recv_record(ctx, &record);

    uint8_t out_data[record.length];

    size_t plain_len = tls_context_decrypt(ctx, &record, out_data);
    tls_record_free(&record);
    return plain_len == 4 && memcmp(out_data, "pong", 4) == 0;
}


int main(int argc, char *argv[])
{
    struct sockaddr_in addr = { 0 };
    const char *host = NULL;
    uint16_t port = DEFAULT_PORT;

    int opt, opt_index;
    while (optind < argc) {
	if ((opt =
	     getopt_long(argc, argv, "p:h", cli_options,
			 &opt_index)) != -1) {
	    switch (opt) {
	    case 'p':{
		    long val = strtol(optarg, NULL, 10);

		    if (errno || val <= 0 || val > UINT16_MAX) {
			fputs("invalid port number provided", stderr);
			return EXIT_FAILURE;
		    }
		    port = (uint16_t) val;
		    break;
		}
	    case 'h':
		print_help(stdout, argv[0]);
		return EXIT_SUCCESS;
	    default:
		print_help(stderr, argv[0]);
		return EXIT_FAILURE;
	    }
	} else {
	    host = argv[optind];
	    ++optind;
	}
    }

    if (!host) {
	print_help(stderr, argv[0]);
	return EXIT_FAILURE;
    }


    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
	struct hostent *entry = gethostbyname(argv[1]);
	if (!entry) {
	    perror("could not solve server address");
	    return EXIT_FAILURE;
	}
	memcpy(&addr.sin_addr, entry->h_addr_list[0],
	       sizeof(struct in_addr));
    }


    struct tls_connection *conn = tls_connect(&addr);
    if (!conn) {
	perror("failed to connect");
	return EXIT_FAILURE;
    }

    struct tls_context *ctx = tls_context_new(conn);
    if (!ctx) {
	tls_connection_close(conn);
	perror("failed to create context");
	return EXIT_FAILURE;
    }

    if (!do_handshake(ctx)) {
	tls_context_free(ctx);
	tls_connection_close(conn);
	fputs("invalid port number provided", stderr);
	perror("TLS hanshsake failed");
	return EXIT_FAILURE;
    }

    if (!ping_request(ctx) || !ping_reply(ctx)) {
	tls_context_free(ctx);
	tls_connection_close(conn);
	fputs("TLS ping failed", stderr);

	return EXIT_FAILURE;
    }
    puts("TLS ping was successful");

    tls_context_free(ctx);
    tls_connection_close(conn);

    return EXIT_SUCCESS;
}
