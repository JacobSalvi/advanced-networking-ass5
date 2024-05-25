#include "test_helpers.h"
#include "tls_impl.h"
#include "unity_fixture.h"
#include "unity.h"
#include <time.h>

static struct tls_context *ctx;
static struct tls_connection_mock connection;
static struct client_hello client_hello;
static time_t client_hello_time;


static void check_client_hello(uint8_t *out)
{
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x01, out[0],
				   "Missing identifier of the handshake message in client hello");
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x000033,
				    (out[1] << 16) +
				    (out[2] << 8) + out[3],
				    "Missing length of the handshake message in client hello");


    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major, out[4],
				   "The client hello should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor, out[5],
				   "The client hello should have version TLS1.2");

    uint32_t gmt_time = 0;
    for (int i = 0; i < 4; ++i)
	gmt_time = (gmt_time << 8) + out[6 + i];

    TEST_ASSERT_EQUAL_HEX32_MESSAGE((uint32_t) client_hello_time,
				    gmt_time,
				    "The client hello client random does not start with the current time");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x0, out[38],
				   "The client hello should contain no session ID");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x0002,
				    (out[39] << 8) + out[40],
				    "The client hello does not contain the length of the cipher suites");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(client_hello.cipher_suite,
				    (out[41] << 8) + out[42],
				    "The client hello does not contain the cipher suite");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x1, out[43],
				   "The client hello does not contain the length of the compression method");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(client_hello.compression_method,
				   out[44],
				   "The client hello does not contain the compression method");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x8,
				    (out[45] << 8) + out[46],
				    "The extensions section of the client hello should start with the length of the section");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0xd,
				    (out[47] << 8) + out[48],
				    "The client hello should contain the sig_algo extension");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x4,
				   (out[49] << 8) + out[50],
				   "The length of the entire extension section is missing");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x2,
				   (out[51] << 8) + out[52],
				   "The length of all the extensions section is missing");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x0401,
				    (out[53] << 8) + out[54],
				    "The sig_algo value is missing");
}


TEST_GROUP(client_hello);

TEST_SETUP(client_hello)
{
    client_hello_time = time(NULL);
    client_hello_init(&client_hello);
    tls_connection_mock_init(&connection);
    ctx = tls_context_new((struct tls_connection *) &connection);

    if (!ctx)
	TEST_FAIL_MESSAGE("Failed to initialize TLS context");
}

TEST_TEAR_DOWN(client_hello)
{
    tls_context_free(ctx);
}

TEST(client_hello, initialize)
{
    uint8_t random_bytes[28];

    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major,
				   client_hello.version.major,
				   "The client hello should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor,
				   client_hello.version.minor,
				   "The client hello should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX32_MESSAGE((uint32_t) client_hello_time,
				    client_hello.random.gmt_unix_time,
				    "The client hello should have the current time as first 4 bytes of the client random");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x003c, client_hello.cipher_suite,
				    "The client hello should support only the TLS_RSA_WITH_AES_128_CBC_SHA256 cipher suite");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x00, client_hello.compression_method,
				    "The client hello should have no compression");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x0401, client_hello.sig_algo,
				    "The signature algo should be RSA-SHA256");
    memcpy(random_bytes, client_hello.random.random_bytes, 28);

    client_hello_init(&client_hello);
    client_hello_time = time(NULL);
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major,
				   client_hello.version.major,
				   "The client hello should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor,
				   client_hello.version.minor,
				   "The client hello should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(client_hello_time,
				    client_hello.random.gmt_unix_time,
				    "The client hello should have the current time as first 4 bytes of the client random");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x003c, client_hello.cipher_suite,
				    "The client hello should support only the TLS_RSA_WITH_AES_128_CBC_SHA256 cipher suite");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x00, client_hello.compression_method,
				    "The client hello should have no compression");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x0401, client_hello.sig_algo,
				    "The signature algo should be RSA-SHA256");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  memcmp(random_bytes,
					 client_hello.random.random_bytes,
					 28),
				  "The second half of the client random should be randomly generated");
}


TEST(client_hello, marshall_no_out)
{
    TEST_ASSERT_EQUAL_MESSAGE(55,
			      client_hello_marshall(&client_hello, NULL),
			      "With no output the marshall function should return the length of the marshalled message");
}


TEST(client_hello, marshalling)
{
    uint8_t result[client_hello_marshall(&client_hello, NULL)];

    TEST_ASSERT_EQUAL_MESSAGE(55,
			      client_hello_marshall(&client_hello, result),
			      "The marshall function should return the length of the message");
    check_client_hello(result);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(client_hello.random.random_bytes,
				     result + 10, 28,
				     "The client random is not being marshalled");
}


TEST(client_hello, sending)
{
    TEST_ASSERT_EQUAL_MESSAGE(1, client_hello_send(ctx),
			      "Failed to send the client hello message");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(handshake, write_buf[0],
				   "The client hello header should start with 0x16");

    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major, write_buf[1],
				   "The client hello should have version TLS1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor, write_buf[2],
				   "The client hello should have version TLS1.2");

    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x0037,
				    (write_buf[3] << 8) + write_buf[4],
				    "The client hello header does not contain the length of the entire handshake message");
    check_client_hello(write_buf + 5);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(write_buf + 11, ctx->client_random,
				     32,
				     "The client hello client random is not being added to the TLS context");
    check_tls_handshake_hash(ctx, write_buf + 5, 55);
}


TEST_GROUP_RUNNER(client_hello)
{
    RUN_TEST_CASE(client_hello, initialize);
    RUN_TEST_CASE(client_hello, marshall_no_out);
    RUN_TEST_CASE(client_hello, marshalling);
    RUN_TEST_CASE(client_hello, sending);
}
