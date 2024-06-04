#include "tls_impl.h"
#include "tls_connection.h"
#include <stddef.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>


// READ ME
// I thank Arnaud Fauconnet, who helped me debug my code.


struct tls_version tls_1_2 = {.major = 3,.minor = 3 };


void num_to_bytes(uint64_t in, uint8_t *out, int count)
{
    // printf("BEGIN\n");
    // TODO: convert in into a list of network-order count bytes and write the result in out
    for (int i = 0; i<count; ++i) {
        uint8_t val = (in >> i*8) & 0xFF;
        out[count-i-1] = val;
        // printf("check HERE: %d\n", out[i]);
    }
}



void tls_record_free(struct tls_record *record)
{
    free(record->fragment);
}



struct tls_context *tls_context_new(struct tls_connection *conn)
{
    EVP_MD_CTX *hashing = EVP_MD_CTX_new();
    if (!hashing)
	return NULL;

    if (!EVP_DigestInit(hashing, EVP_sha256())) {
	EVP_MD_CTX_destroy(hashing);
	return NULL;
    }

    struct tls_context *ctx = malloc(sizeof(struct tls_context));
    if (!ctx) {
	EVP_MD_CTX_destroy(hashing);
	return NULL;
    }
    ctx->version = tls_1_2;
    ctx->connection = conn;
    ctx->handshake_hashing = hashing;
    ctx->client_seq = 0;
    ctx->server_seq = 0;
    return ctx;
}



void tls_context_free(struct tls_context *ctx)
{
    EVP_MD_CTX_free(ctx->handshake_hashing);
    free(ctx);
}



int tls_context_send_record(const struct tls_context *ctx, ...)
{
    uint8_t *buf;
    size_t buf_len = 0;
    const struct tls_record *arg;
    va_list ap;

    va_start(ap, ctx);
    while ((arg = va_arg(ap, const struct tls_record *)))
	 buf_len += 5 + arg->length;
    va_end(ap);

    if (buf_len == 0)
	return 0;

    buf = malloc(buf_len);
    if (!buf)
	return 0;

    uint8_t *p = buf;

    va_start(ap, ctx);
    while ((arg = va_arg(ap, const struct tls_record *))) {
	*p++ = arg->type;
	*p++ = arg->version.major;
	*p++ = arg->version.minor;
	num_to_bytes(arg->length, p, 2);
	p += 2;
	memcpy(p, arg->fragment, arg->length);
	p += arg->length;
    }
    va_end(ap);

    int ret =
	tls_connection_write(ctx->connection, buf, buf_len) < 0 ? 0 : 1;
    free(buf);
    return ret;
}



int tls_context_recv_record(const struct tls_context *ctx,
			    struct tls_record *record)
{
    uint8_t header[5];

    if (tls_connection_read(ctx->connection, header, 5) < 0)
	return 0;

    record->type = header[0];
    record->version.major = header[1];
    record->version.minor = header[2];
    record->length = (header[3] << 8) + header[4];
    if (!(record->fragment = malloc(record->length)))
	return 0;

    if (tls_connection_read
	(ctx->connection, record->fragment, record->length) < 0) {
	free(record->fragment);
	return 0;
    }

    return 1;
}



int tls_context_hash_handshake(const struct tls_context *ctx,
			       const uint8_t *handshake, size_t len)
{

    return EVP_DigestUpdate(ctx->handshake_hashing, handshake, len);
}

int tls_context_handshake_digest(struct tls_context *ctx, uint8_t *out)
{
    if (!out)
	return SHA256_DIGEST_LENGTH;

    EVP_MD_CTX *ctx_copy = EVP_MD_CTX_new();

    if (!ctx_copy)
	return 0;

    if (EVP_MD_CTX_copy(ctx_copy, ctx->handshake_hashing) != 1
	|| EVP_DigestFinal(ctx_copy, out, NULL) != 1) {
	EVP_MD_CTX_free(ctx_copy);
	return 0;
    }

    EVP_MD_CTX_free(ctx_copy);
    return SHA256_DIGEST_LENGTH;
}


int tls_context_derive_keys(struct tls_context *ctx,
			    const struct rsa_premaster_secret *premaster)
{

    // TODO serialize the RSA premaster secret
    // TODO compute the ctx->master_secret by using the PRF function as described in the notes
    uint8_t serialized_premaster[48];
    serialized_premaster[0] = premaster->version.major;
    serialized_premaster[1] = premaster->version.minor;
    memcpy(serialized_premaster + 2, premaster->random, 46);

    uint8_t seed_client_server[77];
    memcpy(seed_client_server, "master secret", 13);
    memcpy(seed_client_server+13, ctx->client_random, 32);
    memcpy(seed_client_server+45, ctx->server_random, 32);

    tls_prf(serialized_premaster, sizeof(serialized_premaster), seed_client_server , sizeof(seed_client_server), ctx->master_secret, sizeof(ctx->master_secret));


    uint8_t key_block[96];

    // TODO compute the key_block using the PRF function as described in the notes
    uint8_t seed_server_client[77];
    memcpy(seed_server_client, "key expansion", 13);
    memcpy(seed_server_client+13, ctx->server_random, 32);
    memcpy(seed_server_client+45, ctx->client_random, 32);
    tls_prf(ctx->master_secret, sizeof(ctx->master_secret), seed_server_client, sizeof(seed_server_client), key_block, 96);

    memcpy(ctx->client_mac_key, key_block, 32);
    memcpy(ctx->server_mac_key, key_block + 32, 32);
    memcpy(ctx->client_enc_key, key_block + 64, 16);
    memcpy(ctx->server_enc_key, key_block + 80, 16);

    return 1;
}



size_t tls_context_encrypt(struct tls_context *ctx,
			   const struct tls_record *record, uint8_t *out)
{

    // If out == NULL just return the length of the cipertext (including the IV)

    // TODO randomly generate 16 bytes of IV and write them in out in clear
    int block_size = EVP_CIPHER_get_block_size(EVP_aes_128_cbc());
    uint8_t padding_len = block_size - (record->length)%block_size;
    size_t cipher_len =
	record->length + SHA256_DIGEST_LENGTH + block_size + padding_len;
    uint8_t iv[block_size];

    RAND_bytes(iv, sizeof(iv));

    if (!out)
	return cipher_len;

    memcpy(out, iv, sizeof(iv));

    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
    if (!enc_ctx)
	return 0;


    // Encrypt the plaintext
    if (EVP_EncryptInit
	(enc_ctx, EVP_aes_128_cbc(), ctx->client_enc_key, iv) != 1) {
	EVP_CIPHER_CTX_free(enc_ctx);
	return 0;
    }
    // This line disables padding, you should do the padding yourself
    // if you remove this line it will use PCKS#7 padding which leads
    // to a bug that is quite nasty to debug
    EVP_CIPHER_CTX_set_padding(enc_ctx, 0);

    // TODO encrypt the plaintext
    // uint8_t data[1];


    int out_len;
    if(EVP_EncryptUpdate(enc_ctx, out+sizeof(iv), &out_len, record->fragment, record->length) != 1){
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    // printf("cipth len is: %ld\n", cipher_len);
    // printf("out_len is: %d\n", out_len);
    cipher_len = out_len+sizeof(iv);


    // TODO compute the HMAC code as described into the nodes and encrypt it by using
    // a second call to the EVP_EncryptUpdate function
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    uint8_t hmac_data[13+record->length];
    num_to_bytes(ctx->client_seq, hmac_data, 8);
    hmac_data[8] = record->type;
    hmac_data[9] = record->version.major;
    hmac_data[10] = record->version.minor;
    num_to_bytes(record->length, hmac_data + 11, 2);
    memcpy(hmac_data + 13, record->fragment, record->length);    
    if(!HMAC(EVP_sha256(), ctx->client_mac_key, sizeof(ctx->client_mac_key), hmac_data, sizeof(hmac_data), hmac, NULL)){
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    if(EVP_EncryptUpdate(enc_ctx, out+cipher_len, &out_len, hmac, sizeof(hmac)) != 1){
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    // printf("cipth len is: %ld\n", cipher_len);
    // printf("out_len is: %d\n", out_len);
    cipher_len += out_len;

    // TODO compute the value used for padding and call the EVP_EncryptUpdate function
    uint8_t padding[padding_len];
    for(int i = 0; i< padding_len; i++){
        padding[i] = padding_len-1;
    }
    if(EVP_EncryptUpdate(enc_ctx, out+cipher_len, &out_len, padding, sizeof(padding)) != 1){
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    // printf("cipth len is: %ld\n", cipher_len);
    // printf("out_len is: %d\n", out_len);
    cipher_len += out_len;

    // TODO remember to finalize the encryption process
    if(EVP_EncryptFinal(enc_ctx, out+cipher_len, &out_len) != 1){
        EVP_CIPHER_CTX_free(enc_ctx);
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    // printf("cipth len is: %ld\n", cipher_len);
    // printf("out_len is: %d\n", out_len);
    cipher_len += out_len;

    EVP_CIPHER_CTX_free(enc_ctx);

    // TODO return the length of the ciphertext including the IV (it should be a multiple of 16)
    // printf("cipth len is: %ld\n", cipher_len);
    // printf("out_len is: %d\n", out_len);
    return cipher_len;
}


size_t tls_context_decrypt(struct tls_context *ctx,
			   const struct tls_record *record, uint8_t *out)
{
    int block_size = EVP_CIPHER_get_block_size(EVP_aes_128_cbc());
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();


    // the length of the plaintext should exclude the IV length
    // (only after decryption you can remove the padding and the HMAC)
    size_t plain_len = record->length - block_size;
    if (!dec_ctx) return 0;
    
    if (EVP_DecryptInit
	(dec_ctx, EVP_aes_128_cbc(), ctx->server_enc_key,
	 record->fragment) != 1) {
	EVP_CIPHER_CTX_free(dec_ctx);
	return 0;
    }

    EVP_CIPHER_CTX_set_padding(dec_ctx, 0);

    // TODO decrypt the fragment in record->fragment
    // TODO finalize the decryption process

    int out_len = 0;
    uint8_t decrypted_text[record->length];
    if(EVP_DecryptUpdate(dec_ctx, decrypted_text, &out_len, record->fragment, record->length) != 1){
        EVP_CIPHER_CTX_free(dec_ctx);
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    plain_len = out_len;

    if(EVP_DecryptFinal(dec_ctx, decrypted_text+out_len, &out_len) != 1){
        EVP_CIPHER_CTX_free(dec_ctx);
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    plain_len += out_len;

    EVP_CIPHER_CTX_free(dec_ctx);
    decrypted_text[plain_len] = 0;


    // TODO compute the length of padding by looking
    // at the last byte of the decrypted text and remove the padding
    uint8_t last_byte = decrypted_text[plain_len-1]+1;
    plain_len = plain_len - last_byte;

    // TODO compute the expected HMAC code using the version in the
    // record, the length of original message (the number of decrypted bytes
    // minus the length of the HMAC code and the length of the padding), and
    // the expected sequence number you can find in ctx->server_seq
    plain_len = plain_len - 32-block_size;

    uint8_t hmac[32];
    uint8_t hmac_data[13+plain_len];
    num_to_bytes(ctx->server_seq, hmac_data, 8);
    hmac_data[8] = record->type;
    hmac_data[9] = record->version.major;
    hmac_data[10] = record->version.minor;
    num_to_bytes(plain_len, hmac_data + 11, 2);
    memcpy(hmac_data + 13, decrypted_text+block_size, plain_len); 
    if(!HMAC(EVP_sha256(), ctx->server_mac_key, 32, hmac_data, sizeof(hmac_data), hmac , NULL)){
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    // TODO copy ONLY the plaintext into out, i.e. remove padding and HMAC
    // plain_len = plain_len - 32-block_size;
    // if(!out){
    //     return plain_len;
    // }
    uint8_t old_hmac[32];
    memcpy(old_hmac, decrypted_text+block_size+plain_len, 32);
    if(memcmp(hmac, old_hmac, 32)!=0){
        return 0;
    }

    if(!out){
        return plain_len;
    }

    memcpy(out, decrypted_text+block_size, plain_len);
    return plain_len;
}


void client_hello_init(struct client_hello *hello)
{
    // TODO initialize the fields of a client hello message
    // You should support only the TLS_RSA_WITH_AES_128_CBC_SHA256
    // cipher suite and no compression.
    //
    // The client does not have to restore a previous session.
    hello->version = tls_1_2;
    hello->random.gmt_unix_time = time(NULL);
    RAND_bytes(hello->random.random_bytes, 28);
    // hello->cipher_suite = { 0x00,0x3C };
    hello->cipher_suite = 0x003C;
    hello->compression_method = 0x00;

    hello->sig_algo = 0x0401;
}



size_t client_hello_marshall(const struct client_hello *hello,
			     uint8_t *out)
{
    size_t len = 55;

    if (!out)
	return len;

    // TODO write the contenst of the client hello message into out
    // The required TLS extensions are already done for you
    //
    // The client does not have to restore a previous session.

    // add identifier
    out[0] = 0x01;
    // add message length
    num_to_bytes(len-4, out+1, 3);

    // add tls version supported
    num_to_bytes(hello->version.major, out+4, 1);
    num_to_bytes(hello->version.minor, out+5, 1);

    // add client random
    num_to_bytes(hello->random.gmt_unix_time, out+6, 4);
    memcpy(out+10, hello->random.random_bytes, 28);
    // add session id
    out[38] = 0x00;

    // add cipher suite
    num_to_bytes(2, out+39, 2);
    num_to_bytes(hello->cipher_suite, out+41, 2);

    // add compression methods
    num_to_bytes(1, out+43, 1);
    num_to_bytes(hello->compression_method, out+44, 1);

    num_to_bytes(8, out + 45, 2);
    num_to_bytes(0xd, out + 47, 2);
    num_to_bytes(0x4, out + 49, 2);
    num_to_bytes(0x2, out + 51, 2);
    num_to_bytes(hello->sig_algo, out + 53, 2);

    return len;
}



int client_hello_send(struct tls_context *ctx)
{
    struct client_hello hello;
    client_hello_init(&hello);

    uint8_t data[client_hello_marshall(&hello, NULL)];
    struct tls_record record = {
	.version = tls_1_2,
	.length = sizeof(data),
	.type = handshake,
	.fragment = data
    };

    client_hello_marshall(&hello, data);

    memcpy(ctx->client_random, data + 6, sizeof(ctx->client_random));

    if (tls_context_hash_handshake(ctx, data, sizeof(data)) != 1)
	return 0;

    return tls_context_send_record(ctx, &record, NULL);
}



int server_hello_recv(struct tls_context *ctx, struct server_hello *out)
{
    struct tls_record record;

    if (!tls_context_recv_record(ctx, &record))
	return 0;

    if (record.fragment[0] != 0x2) {
	tls_record_free(&record);
	return 0;
    }


    // TODO use the contents of record.fragment to populate the fields of out
    memcpy(&out->version.major, record.fragment+4, 1);
    memcpy(&out->version.minor, record.fragment +5, 1);
    uint32_t server_time = 0;
    for (int i = 0; i < 4; ++i){
	    server_time = (server_time << 8) + record.fragment[6 + i];
    }
    memcpy(&out->random.gmt_unix_time, &server_time, 4);
    memcpy(&out->random.random_bytes, record.fragment+10, 28);
    // populate ctx
    memcpy(ctx->server_random, record.fragment+6, 32);
    memcpy(&out->session_id_len, record.fragment+38, 1);
    memcpy(&out->session_id, record.fragment+39, out->session_id_len);
    uint16_t cipher_suite = (*(record.fragment+39+out->session_id_len) << 8) + *(record.fragment+40+out->session_id_len);
    memcpy(&out->cipher_suite, &cipher_suite, 2);
    memcpy(&out->compression_method, record.fragment+41+out->session_id_len, 1);


    int ret =
	tls_context_hash_handshake(ctx, record.fragment, record.length);
    tls_record_free(&record);
    return ret == 1;
}



X509 *server_cert_recv(const struct tls_context *ctx)
{
    struct tls_record record;

    if (!tls_context_recv_record(ctx, &record))
	return 0;

    if (record.fragment[0] != 0xb)
	goto error_handling;

    if (!tls_context_hash_handshake(ctx, record.fragment, record.length))
	goto error_handling;

    // TODO read the certificate chain and return the first certificate (you may assume that there is only one certificate)
    // Hint: use the d2i_X509 OpenSSL function to deserialize the DER-encoded structure
    X509 *cert = NULL;
    long cert_length = (*(record.fragment + 7) << 16) | (*(record.fragment+8)<<8) | (*(record.fragment +9));
    const uint8_t * first_cert = record.fragment + 10;
    d2i_X509(&cert, &first_cert, cert_length);

    tls_record_free(&record);
    return cert;
  error_handling:
    tls_record_free(&record);
    return 0;
}



int server_hello_done_recv(const struct tls_context *ctx)
{
    struct tls_record record;

    if (!tls_context_recv_record(ctx, &record))
	return 0;

    if (record.fragment[0] != 0xe)
	goto error_handling;


    if (!tls_context_hash_handshake(ctx, record.fragment, record.length))
	goto error_handling;

    tls_record_free(&record);
    return 1;

  error_handling:
    tls_record_free(&record);
    return 0;
}



void rsa_premaster_secret_init(struct rsa_premaster_secret *exchange)
{
    // TODO Generate a RSA premaster secret
    exchange->version.major = tls_1_2.major;
    exchange->version.minor = tls_1_2.minor;
    RAND_bytes(exchange->random, 46);

}



size_t rsa_premaster_marshall(const struct rsa_premaster_secret *premaster,
			      X509 *cert, uint8_t *out)
{
    size_t cipher_len = 0;
    uint8_t plain[48];

    plain[0] = premaster->version.major;
    plain[1] = premaster->version.minor;
    memcpy(plain + 2, premaster->random, 46);

    EVP_PKEY *key = X509_get_pubkey(cert);
    if (!key)
	return 0;

    EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!key) {
	EVP_PKEY_free(key);
	return 0;
    }

    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0)
	goto end;


    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_PADDING) <= 0)
	goto end;


    if (EVP_PKEY_encrypt(enc_ctx, NULL, &cipher_len, plain, sizeof(plain))
	<= 0) {
	cipher_len = 0;
	goto end;
    }

    if (!out)
	goto end;
    *out = 0x10;
    num_to_bytes(cipher_len + 2, out + 1, 3);
    num_to_bytes(cipher_len, out + 4, 2);

    if (EVP_PKEY_encrypt
	(enc_ctx, out + 6, &cipher_len, plain, sizeof(plain)) <= 0)
	cipher_len = 0;

  end:
    EVP_PKEY_CTX_free(enc_ctx);
    EVP_PKEY_free(key);
    return cipher_len + 6;
}



int compute_finished(struct tls_context *ctx, uint8_t *out)
{
    uint8_t vrfy_seed[15 + SHA256_DIGEST_LENGTH];

    memcpy(vrfy_seed, "client finished", 15);

    if (!tls_context_handshake_digest(ctx, vrfy_seed + 15)
	|| !tls_prf(ctx->master_secret, 48, vrfy_seed, sizeof(vrfy_seed),
		    out + 4, 12))
	return 0;
    *out = 0x14;
    num_to_bytes(12, out + 1, 3);

    return 1;
}

int key_agreement(struct tls_context *ctx,
		  const struct rsa_premaster_secret *premaster, X509 *cert)
{
    uint8_t chg_spec_msg = 0x1;
    uint8_t key_exc_frag[rsa_premaster_marshall(premaster, cert, NULL)];

    uint8_t client_verify[80];
    uint8_t vrfy[16];


    struct tls_record key_exc = {
	.type = handshake,
	.version = ctx->version,
	.length = sizeof(key_exc_frag),
	.fragment = key_exc_frag
    };

    struct tls_record chg_spec = {
	.type = change_cipher_spec,
	.version = ctx->version,
	.length = 1,
	.fragment = &chg_spec_msg
    };

    struct tls_record finished = {
	.type = handshake,
	.length = sizeof(vrfy),
	.version = ctx->version,
	.fragment = vrfy
    };

    if (!tls_context_derive_keys(ctx, premaster)
	|| !rsa_premaster_marshall(premaster, cert, key_exc_frag)
	|| !tls_context_hash_handshake(ctx, key_exc.fragment,
				       key_exc.length)
	|| !compute_finished(ctx, vrfy)
	|| !tls_context_hash_handshake(ctx, finished.fragment,
				       finished.length)
	|| !tls_context_encrypt(ctx, &finished, client_verify))
	return 0;

    finished.length = sizeof(client_verify);
    finished.fragment = client_verify;
    ++ctx->client_seq;

    return tls_context_send_record(ctx, &key_exc, &chg_spec, &finished,
				   NULL);
}

int verify_server(struct tls_context *ctx)
{
    struct tls_record chg_spec;
    struct tls_record finished;
    uint8_t vrfy_seed[15 + SHA256_DIGEST_LENGTH];
    uint8_t vrfy[12];
    uint8_t received_vrfy[80];

    memcpy(vrfy_seed, "server finished", 15);

    if (!tls_context_handshake_digest(ctx, vrfy_seed + 15)
	|| !tls_prf(ctx->master_secret, 48, vrfy_seed, sizeof(vrfy_seed),
		    vrfy, 12)
	|| !tls_context_recv_record(ctx, &chg_spec))
	return 0;

    tls_record_free(&chg_spec);

    if (!tls_context_recv_record(ctx, &finished))
	return 0;
    if (finished.length != 80
	|| !tls_context_decrypt(ctx, &finished, received_vrfy)
	|| memcmp(vrfy, received_vrfy + 4, 12) != 0) {
	tls_record_free(&finished);
	return 0;
    }
    tls_record_free(&finished);
    ++ctx->server_seq;

    return 1;
}

int tls_prf(const uint8_t *secret, size_t secret_len, const uint8_t *seed,
	    size_t seed_len, uint8_t *out, size_t out_len)
{
    uint8_t A[SHA256_DIGEST_LENGTH + seed_len];
    uint8_t result[SHA256_DIGEST_LENGTH];

    HMAC(EVP_sha256(), secret, secret_len, seed, seed_len, A, NULL);
    memcpy(A + SHA256_DIGEST_LENGTH, seed, seed_len);

    while (1) {
	HMAC(EVP_sha256(), secret, secret_len, A,
	     SHA256_DIGEST_LENGTH + seed_len, result, NULL);

	if (out_len <= SHA256_DIGEST_LENGTH) {
	    memcpy(out, result, out_len);
	    break;
	}

	memcpy(out, result, SHA256_DIGEST_LENGTH);
	HMAC(EVP_sha256(), secret, secret_len, A, SHA256_DIGEST_LENGTH,
	     result, NULL);
	memcpy(A, result, SHA256_DIGEST_LENGTH);

	out += SHA256_DIGEST_LENGTH;
	out_len -= SHA256_DIGEST_LENGTH;
    }

    return 1;
}
