#ifndef TLS_IMPL_INCLUDED
#define TLS_IMPL_INCLUDED

#include "tls_connection.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/x509.h>

struct tls_version {
    uint8_t major;
    uint8_t minor;
};

extern struct tls_version tls_1_2;

enum content_type {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23
};

struct tls_record {
    enum content_type type;
    struct tls_version version;
    uint16_t length;
    uint8_t *fragment;
};

struct tls_context {
    struct tls_version version;

    uint8_t client_random[32];
    uint8_t server_random[32];

    uint8_t master_secret[48];
    uint8_t client_mac_key[32];
    uint8_t server_mac_key[32];
    uint8_t client_enc_key[16];
    uint8_t server_enc_key[16];

    uint64_t client_seq;
    uint64_t server_seq;

    EVP_MD_CTX *handshake_hashing;
    struct tls_connection *connection;
};

struct hello_random {
    uint32_t gmt_unix_time;
    uint8_t random_bytes[28];
};

struct client_hello {
    struct tls_version version;
    struct hello_random random;
    uint16_t cipher_suite;
    uint8_t compression_method;
    uint16_t sig_algo;
};

struct server_hello {
    struct tls_version version;
    struct hello_random random;
    uint8_t session_id_len;
    uint8_t session_id[32];
    uint16_t cipher_suite;
    uint8_t compression_method;
};

struct rsa_premaster_secret {
    struct tls_version version;
    uint8_t random[46];
};


void tls_record_free(struct tls_record *record);
struct tls_context *tls_context_new(struct tls_connection *connection);
void tls_context_free(struct tls_context *ctx);
int tls_context_send_record(const struct tls_context *ctx, ...);
int tls_context_recv_record(const struct tls_context *ctx,
			    struct tls_record *record);
int tls_context_hash_handshake(const struct tls_context *ctx,
			       const uint8_t * handshake, size_t len);
int tls_context_handshake_digest(struct tls_context *ctx, uint8_t * out);
int tls_context_derive_keys(struct tls_context *ctx,
			    const struct rsa_premaster_secret *premaster);
size_t tls_context_encrypt(struct tls_context *ctx,
			   const struct tls_record *record, uint8_t * out);
size_t tls_context_decrypt(struct tls_context *ctx,
			   const struct tls_record *record, uint8_t * out);


void client_hello_init(struct client_hello *hello);
size_t client_hello_marshall(const struct client_hello *hello,
			     uint8_t * out);
int client_hello_send(struct tls_context *ctx);


int server_hello_recv(struct tls_context *ctx, struct server_hello *out);
X509 *server_cert_recv(const struct tls_context *ctx);
int server_hello_done_recv(const struct tls_context *ctx);


void rsa_premaster_secret_init(struct rsa_premaster_secret *premaster);
size_t rsa_premaster_marshall(const struct rsa_premaster_secret *premaster,
			      X509 * cert, uint8_t * out);
int compute_finished(struct tls_context *ctx, uint8_t * out);

int key_agreement(struct tls_context *ctx,
		  const struct rsa_premaster_secret *premaster,
		  X509 * cert);
int verify_server(struct tls_context *ctx);



int tls_prf(const uint8_t * secret, size_t secret_len,
	    const uint8_t * seed, size_t seed_len, uint8_t * out,
	    size_t out_len);
void num_to_bytes(uint64_t value, uint8_t * out, int out_len);


#endif
