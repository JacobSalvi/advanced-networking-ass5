#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/prov_ssl.h>
#include <openssl/tls1.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <libgen.h>
#include <getopt.h>

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
    fprintf(fp, "Usage: %s [options]\n\n", basename(path));

    fprintf(fp, "-p <port>, --port <port>\n");
    fprintf(fp,
	    "                  The port the port should start listening on (default: %u)\n",
	    DEFAULT_PORT);
    fprintf(fp, "-h, --help\n");
    fprintf(fp, "                  Display this help and exit\n");
}


int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void debug_callback(const SSL *s, int where, int ret)
{
    const char *str;
    int w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
	str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
	str = "SSL_accept";
    else
	str = "undefined";

    if (where & SSL_CB_LOOP) {
	fprintf(stderr, "%s:%s\n", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
	str = (where & SSL_CB_READ) ? "read" : "write";
	fprintf(stderr, "SSL3 alert %s:%s:%s\n",
		str,
		SSL_alert_type_string_long(ret),
		SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
	if (ret == 0)
	    fprintf(stderr, "%s:failed in %s\n",
		    str, SSL_state_string_long(s));
	else if (ret < 0) {
	    fprintf(stderr, "%s:error in %s\n",
		    str, SSL_state_string_long(s));
	}
    }
}

void configure_context(SSL_CTX *ctx)
{
    EVP_PKEY *server_key = NULL;
    X509 *cert = NULL;

    if (access("server.key", F_OK) == 0) {
	FILE *fp = fopen("server.key", "r");

	if (!fp) {
	    perror("failed to read key file");
	    exit(EXIT_FAILURE);
	}

	PEM_read_PrivateKey(fp, &server_key, NULL, NULL);
	fclose(fp);

    } else {
	server_key = EVP_RSA_gen(2048);
	FILE *fp = fopen("server.key", "w");

	if (!fp) {
	    perror("failed to create key file");
	    exit(EXIT_FAILURE);
	}

	PEM_write_PrivateKey(fp, server_key, NULL, NULL, 0, NULL, NULL);
	fclose(fp);
    }

    if (access("server.crt", F_OK) == 0) {
	FILE *fp = fopen("server.crt", "r");

	if (!fp) {
	    perror("failed to read certificate file");
	    exit(EXIT_FAILURE);
	}

	PEM_read_X509(fp, &cert, NULL, NULL);
	PEM_read_PrivateKey(fp, &server_key, NULL, NULL);
	fclose(fp);
    } else {
	cert = X509_new();

	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 365);
	X509_set_pubkey(cert, server_key);

	X509_NAME *name = X509_get_subject_name(cert);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
				   (unsigned char *) "CH", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
				   (unsigned char *)
				   "Universita della Svizzera italiana",
				   -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (unsigned char *) "usi.ch", -1, -1, 0);
	X509_sign(cert, server_key, EVP_sha256());

	FILE *fp = fopen("server.crt", "w");

	if (!fp) {
	    perror("failed to create certificate file");
	    exit(EXIT_FAILURE);
	}
	PEM_write_X509(fp, cert);
	fclose(fp);
    }

    if (SSL_CTX_use_certificate(ctx, cert) <= 0
	|| SSL_CTX_use_PrivateKey(ctx, server_key) <= 0
	|| SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) <= 0
	|| SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION) <= 0
	|| SSL_CTX_set_cipher_list(ctx, "AES128-SHA256") <= 0
	|| SSL_CTX_set_options(ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET) <= 0
	|| SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET) <= 0
	|| SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION) <= 0
	|| SSL_CTX_set_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC) <= 0) {
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }


    SSL_CTX_set_info_callback(ctx, debug_callback);
}

int main(int argc, char *argv[])
{
    int sock;
    SSL_CTX *ctx;
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
	    print_help(stderr, argv[0]);
	    return EXIT_FAILURE;
	}
    }


    signal(SIGPIPE, SIG_IGN);

    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(port);

    while (1) {
	struct sockaddr_in addr;
	unsigned int len = sizeof(addr);
	SSL *ssl;
	const char reply[] = "pong";

	int client = accept(sock, (struct sockaddr *) &addr, &len);
	if (client < 0) {
	    perror("unable to accept connection");
	    exit(EXIT_FAILURE);
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client);

	if (SSL_accept(ssl) <= 0) {
	    ERR_print_errors_fp(stderr);
	    continue;
	}

	char request[10];
	char cli_addr[INET_ADDRSTRLEN];
	int n = SSL_read(ssl, request, sizeof(request));
	if (n <= 0) {
	    perror("failed to read from client");
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	    close(client);
	    continue;
	}
	request[n] = '\0';


	printf("received %s from %s:%d\n", request,
	       inet_ntop(AF_INET, &addr.sin_addr, cli_addr,
			 sizeof(cli_addr)), ntohs(addr.sin_port));

	SSL_write(ssl, reply, strlen(reply));
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}
