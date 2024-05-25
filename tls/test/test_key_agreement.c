#include "test_helpers.h"
#include "tls_impl.h"
#include "unity.h"
#include "unity_fixture.h"
#include <string.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

static struct tls_context *ctx;
static struct tls_connection_mock connection;
struct rsa_premaster_secret premaster;
static EVP_PKEY *server_key;
static X509 *cert;

static uint8_t cli_finished[] = {
    0x14, 0x00, 0x00, 0x0c, 0x33, 0xf6, 0xc1, 0x88,
    0x31, 0xf4, 0xbb, 0x84, 0x5c, 0x66, 0xbb, 0xd5
};

static void check_premaster(uint8_t *out)
{
    uint8_t msg[48];

    msg[0] = premaster.version.major;
    msg[1] = premaster.version.minor;
    memcpy(msg + 2, premaster.random, 46);

    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x10, out[0],
				   "The client key exchange header should have type 0x10");
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(258,
				    (out[1] << 16) + (out[2] << 8) +
				    out[3],
				    "The length of the client key exchange message is missing");
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(256, (out[4] << 8) + out[5],
				    "The length of the encrypted pre-master is missing");

    EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(server_key, NULL);
    if (!enc_ctx) {
	EVP_PKEY_CTX_free(enc_ctx);
	TEST_FAIL_MESSAGE("Failed to create decryption context");
    }

    if (EVP_PKEY_decrypt_init(enc_ctx) != 1) {
	EVP_PKEY_CTX_free(enc_ctx);
	TEST_FAIL_MESSAGE("Failed to initialize decryption");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_PADDING) != 1) {
	EVP_PKEY_CTX_free(enc_ctx);
	TEST_FAIL_MESSAGE("Failed to set padding");
    }


    size_t plain_len;
    if (EVP_PKEY_decrypt(enc_ctx, NULL, &plain_len, out + 6, 256) != 1) {
	EVP_PKEY_CTX_free(enc_ctx);
	TEST_FAIL_MESSAGE("Failed to get plaintext length");
    }

    uint8_t plain[plain_len];

    if (EVP_PKEY_decrypt(enc_ctx, plain, &plain_len, out + 6, 256) != 1) {
	EVP_PKEY_CTX_free(enc_ctx);
	TEST_FAIL_MESSAGE("Failed to decrypt message");
    }

    TEST_ASSERT_EQUAL_MESSAGE(sizeof(msg), plain_len,
			      "The client key exchange should contain the RSA pre-master key encrypted with the key from the server certificate");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(plain, msg, sizeof(msg),
				     "The client key exchange should contain the RSA pre-master key encrypted with the key from the server certificate");
    EVP_PKEY_CTX_free(enc_ctx);
}


TEST_GROUP(key_agreement);

TEST_SETUP(key_agreement)
{
    init_server_certificate(&server_key, &cert);
    rsa_premaster_secret_init(&premaster);
    tls_connection_mock_init(&connection);
    ctx = tls_context_new((struct tls_connection *) &connection);
    if (!ctx)
	TEST_FAIL_MESSAGE("Failed to initialize the TLS context");
}


TEST_TEAR_DOWN(key_agreement)
{
    X509_free(cert);
    EVP_PKEY_free(server_key);
    tls_context_free(ctx);
}


TEST(key_agreement, premaster_init)
{
    uint8_t random_bytes[46];

    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major, premaster.version.major,
				   "The client hello should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor, premaster.version.minor,
				   "The client hello should have version TLS1.2");
    memcpy(random_bytes, premaster.random, 46);

    rsa_premaster_secret_init(&premaster);
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major, premaster.version.major,
				   "The client hello should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor, premaster.version.minor,
				   "The client hello should have version TLS1.2");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  memcmp(random_bytes,
					 premaster.random,
					 46),
				  "The random part of the RSA pre-master secret should be randomly generated");
}


TEST(key_agreement, premaster_marshall_no_out)
{
    TEST_ASSERT_EQUAL_MESSAGE(262,
			      rsa_premaster_marshall(&premaster, cert,
						     NULL),
			      "With no output the marshall function should return the length of the marshalled message");
}


TEST(key_agreement, premaster_marshall)
{
    uint8_t result[rsa_premaster_marshall(&premaster, cert, NULL)];

    TEST_ASSERT_EQUAL_MESSAGE(262,
			      rsa_premaster_marshall(&premaster, cert,
						     result),
			      "The marshall function should return the length of the message");
    check_premaster(result);
}



TEST(key_agreement, compute_finished)
{
    uint8_t finished[16];

    tls_context_mock(ctx);
    premaster_mock(&premaster);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");
    TEST_ASSERT_EQUAL_MESSAGE(1, compute_finished(ctx, finished),
			      "The marshall function should return the length of the message");

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(cli_finished, finished,
				     sizeof(cli_finished),
				     "The client final does not match the expected one");
}




TEST(key_agreement, sending)
{
    uint8_t *p = write_buf;

    TEST_ASSERT_EQUAL_MESSAGE(1, key_agreement(ctx,
					       &premaster,
					       cert),
			      "Failed to send the client key exchange message");

    // Checking client key exchange message
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(handshake, *p,
				   "The client key exchange header should be an handshake message");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major, p[1],
				   "The client key exchange should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor, p[2],
				   "The client key exchange should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(262,
				    (p[3] << 8) + p[4],
				    "The client key exchange header does not contain the length of the entire handshake message");
    check_premaster(p + 5);
    p += 267;

    // Checking change cipher spec message
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(change_cipher_spec, *p,
				   "The change cipher spec header should have change cipher spec type");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major, p[1],
				   "The change cipher spec should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor, p[2],
				   "The change cipher spec should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(1,
				    (p[3] << 8) + p[4],
				    "The change cipher spec header does not contain the length of the entire message");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(1, p[5],
				   "The change cipher spec message should have 0x1 as message");

    p += 6;

    // Checking finished message
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(handshake, *p,
				   "The client finished should be an handshake message");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major, p[1],
				   "The client finished should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor, p[2],
				   "The client finished should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(80,
				    (p[3] << 8) + p[4],
				    "The client finished header does not contain the length of the entire message");
    TEST_ASSERT_EQUAL_MESSAGE(0x1, ctx->client_seq,
			      "The client sequence number should be incremented as the client has sent the first encrypted message");
}


TEST(key_agreement, server_finished)
{
    uint8_t server_verification[] = {
	0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03,
	0x03, 0x00, 0x50, 0xfb, 0x35, 0x36, 0x0b, 0x59,
	0x96, 0xdf, 0xd6, 0xbd, 0x96, 0x91, 0x75, 0xd5,
	0xc3, 0x8e, 0xb4, 0x79, 0x36, 0x60, 0xff, 0x41,
	0x81, 0x90, 0x46, 0x3a, 0x98, 0xa3, 0x27, 0x8f,
	0xc5, 0x43, 0xb0, 0xe4, 0xea, 0xdf, 0x2d, 0xb4,
	0x41, 0xbb, 0x66, 0xf2, 0xb4, 0x31, 0xaa, 0xd2,
	0x3a, 0xb8, 0x94, 0xd2, 0x1a, 0xa4, 0xf9, 0x57,
	0x36, 0x3b, 0x3b, 0xd4, 0xdd, 0x72, 0x4e, 0x5d,
	0x41, 0xab, 0x7b, 0x4c, 0x06, 0x68, 0x67, 0x67,
	0xf7, 0x24, 0x6b, 0xcf, 0x6c, 0x6e, 0xbc, 0x55,
	0xba, 0x4d, 0xc9
    };



    memcpy(read_buf, server_verification, sizeof(server_verification));
    tls_context_mock(ctx);
    premaster_mock(&premaster);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");

    if (!tls_context_hash_handshake
	(ctx, cli_finished, sizeof(cli_finished)))
	TEST_FAIL_MESSAGE("Failed to mock the client finished message");

    TEST_ASSERT_EQUAL_MESSAGE(1, verify_server(ctx),
			      "Server finished verification failed");
    TEST_ASSERT_EQUAL_MESSAGE(1, ctx->server_seq,
			      "The server sequence number should be incremented when the verification succeeds");
}


TEST(key_agreement, server_finished_invalid)
{
    uint8_t server_verification[] = {
	0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03,
	0x03, 0x00, 0x50, 0xfb, 0x35, 0x36, 0x0b, 0x59,
	0x96, 0xdf, 0xd6, 0xbd, 0x96, 0x91, 0x75, 0xd5,
	0xc3, 0x8e, 0xb4, 0x79, 0x36, 0x60, 0xff, 0x41,
	0x81, 0x90, 0x46, 0x3a, 0x98, 0xa3, 0x27, 0x8f,
	0xc5, 0x43, 0xb0, 0xe4, 0xea, 0xdf, 0x2d, 0xb4,
	0x41, 0xbb, 0x66, 0xf2, 0xb4, 0x31, 0xaa, 0xd2,
	0x3a, 0xb8, 0x94, 0xd2, 0x1a, 0xa4, 0xf9, 0x57,
	0x36, 0x3b, 0x3b, 0xd4, 0xdd, 0x72, 0x4e, 0x5d,
	0x41, 0xab, 0x7b, 0x4c, 0x06, 0x68, 0x67, 0x67,
	0xf7, 0x24, 0x6b, 0xcf, 0x6c, 0x6e, 0xbc, 0x55,
	0xba, 0x4d, 0xc9
    };

    uint8_t tampered_finished[sizeof(cli_finished)];

    memcpy(tampered_finished, cli_finished, sizeof(cli_finished));

    tampered_finished[10] = 0xff;

    memcpy(read_buf, server_verification, sizeof(server_verification));
    tls_context_mock(ctx);
    premaster_mock(&premaster);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");


    if (!tls_context_hash_handshake
	(ctx, tampered_finished, sizeof(tampered_finished)))
	TEST_FAIL_MESSAGE("Failed to mock the client finished message");

    TEST_ASSERT_EQUAL_MESSAGE(0, verify_server(ctx),
			      "Server finished verification should fail when the server finished message does not match the client computed one");
    TEST_ASSERT_EQUAL_MESSAGE(0, ctx->server_seq,
			      "The server sequence number should not be incremented when the verification fails");
}



TEST_GROUP_RUNNER(key_agreement)
{
    RUN_TEST_CASE(key_agreement, premaster_init);
    RUN_TEST_CASE(key_agreement, premaster_marshall_no_out);
    RUN_TEST_CASE(key_agreement, premaster_marshall);
    /* RUN_TEST_CASE(key_agreement, finished_marshall_no_out); */
    RUN_TEST_CASE(key_agreement, compute_finished);
    RUN_TEST_CASE(key_agreement, sending);
    RUN_TEST_CASE(key_agreement, server_finished);
    RUN_TEST_CASE(key_agreement, server_finished_invalid);
}
