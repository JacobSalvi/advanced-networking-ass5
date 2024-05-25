#include "unity_fixture.h"
#include "unity.h"
#include "test_helpers.h"


static struct tls_context *ctx;
static struct tls_connection_mock connection;
static EVP_PKEY *server_key;
static X509 *cert;

TEST_GROUP(server_certificate);

TEST_SETUP(server_certificate)
{
    init_server_certificate(&server_key, &cert);
    int cert_len = i2d_X509(cert, NULL);
    TEST_ASSERT_LESS_THAN_INT(sizeof(read_buf), cert_len + 15);

    tls_connection_mock_init(&connection);
    ctx = tls_context_new((struct tls_connection *) &connection);

    if (!ctx)
	TEST_FAIL_MESSAGE("Failed to initialize TLS context");

    read_buf[0] = 0x16;
    read_buf[1] = 0x03;
    read_buf[2] = 0x03;

    uint8_t *buf = read_buf + 3;
    uint32_t len = cert_len + 10;

    for (int i = 8; i >= 0; i -= 8)
	*buf++ = (len >> i) & 0xff;
    *buf++ = 0xb;
    len -= 4;

    for (int i = 16; i >= 0; i -= 8)
	*buf++ = (len >> i) & 0xff;
    len -= 3;

    for (int i = 16; i >= 0; i -= 8)
	*buf++ = (len >> i) & 0xff;
    len -= 3;

    for (int i = 16; i >= 0; i -= 8)
	*buf++ = (len >> i) & 0xff;

    i2d_X509(cert, &buf);
}

TEST_TEAR_DOWN(server_certificate)
{
    X509_free(cert);
    EVP_PKEY_free(server_key);
    tls_context_free(ctx);
}

TEST(server_certificate, receiving)
{
    X509 *server_cert = server_cert_recv(ctx);
    TEST_ASSERT_NOT_NULL_MESSAGE(server_cert,
				 "When the server certificate is valid a pointer to the certificate should be returned");

    int cert_len = i2d_X509(server_cert, NULL);
    uint8_t buf[cert_len];
    uint8_t *p = buf;

    i2d_X509(server_cert, &p);

    TEST_ASSERT_EQUAL(i2d_X509(cert, NULL), cert_len);
    TEST_ASSERT_EQUAL_MEMORY(buf, read_buf + 15, cert_len);
    check_tls_handshake_hash(ctx, read_buf + 5, cert_len + 10);
    X509_free(server_cert);
}

TEST(server_certificate, invalid_message)
{
    read_buf[5] = 0x32;
    TEST_ASSERT_NULL_MESSAGE(server_cert_recv(ctx),
			     "The server certificate should return NULL if the message format is invalid");
}

TEST_GROUP_RUNNER(server_certificate)
{
    RUN_TEST_CASE(server_certificate, receiving);
    RUN_TEST_CASE(server_certificate, invalid_message);
}
