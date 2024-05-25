#ifndef TEST_HELPERS_INCLUDED
#define TEST_HELPERS_INCLUDED

#include "tls_connection.h"
#include "tls_impl.h"
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

struct tls_connection_mock {
    struct tls_connection super;
    int closed;
    size_t write_index;
    size_t read_index;
};

extern int failure;
extern double interrupt_probability;
extern uint8_t write_buf[2000];
extern uint8_t read_buf[2000];

void tls_connection_mock_init(struct tls_connection_mock *conn);
void check_tls_handshake_hash(struct tls_context *ctx, uint8_t * in,
			      size_t in_len);
void init_server_certificate(EVP_PKEY ** key, X509 ** cert);
void tls_context_mock(struct tls_context *ctx);
void premaster_mock(struct rsa_premaster_secret *premaster);


#endif
