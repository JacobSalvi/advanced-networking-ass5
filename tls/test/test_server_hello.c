#include "unity_fixture.h"
#include "unity.h"
#include "test_helpers.h"
#include <openssl/rand.h>

static struct tls_context *ctx;
static struct tls_connection_mock connection;
static time_t server_hello_time;

TEST_GROUP(server_hello);

TEST_SETUP(server_hello)
{
    int session_id_len = rand() % 33;
    int len = 0x26 + session_id_len;

    uint8_t header[] = {
	0x16, 0x3, 0x3, 0x0, len + 4, 0x2,
	0x0, 0x0, len, 0x3, 0x3,
    };

    server_hello_time = time(NULL);
    uint8_t *buf = read_buf;

    memcpy(buf, header, sizeof(header));
    buf += sizeof(header);

    for (int i = 24; i >= 0; i -= 8)
	*buf++ = (server_hello_time >> i) & 0xff;

    RAND_bytes(buf, 28);
    buf += 28;

    *buf++ = session_id_len;
    RAND_bytes(buf, session_id_len);
    buf += session_id_len;

    uint16_t cipher = rand() % UINT16_MAX;
    *buf++ = (cipher >> 8) & 0xff;
    *buf++ = cipher & 0xff;

    *buf = rand() % UINT8_MAX;

    tls_connection_mock_init(&connection);
    ctx = tls_context_new((struct tls_connection *) &connection);
    if (!ctx)
	TEST_FAIL_MESSAGE("Failed to initialize TLS context");
}

TEST_TEAR_DOWN(server_hello)
{
    tls_context_free(ctx);
}

TEST(server_hello, receiving)
{
    struct server_hello hello;

    TEST_ASSERT_EQUAL_MESSAGE(1, server_hello_recv(ctx, &hello),
			      "Failed to receive server hello");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(write_buf[9], hello.version.major,
				   "The server hello unmarshalling of the major version is wrong");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(write_buf[10], hello.version.minor,
				   "The server hello unmarshalling of the minor version is wrong");

    uint32_t server_time = 0;
    for (int i = 0; i < 4; ++i)
	server_time = (server_time << 8) + read_buf[11 + i];

    TEST_ASSERT_EQUAL_HEX32_MESSAGE(server_time,
				    hello.random.gmt_unix_time,
				    "Server hello server time in server random was unmarshalled incorrectly");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(read_buf + 15,
				     hello.random.random_bytes, 28,
				     "Server hello random bytes in server random were unmarshalled incorrectly");

    TEST_ASSERT_EQUAL_HEX8_MESSAGE(read_buf[43], hello.session_id_len,
				   "Server hello session ID length was unmarshalled incorrectly");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(hello.session_id, read_buf + 44,
				     hello.session_id_len,
				     "Server hello session ID was unmarshalled incorrectly");

    size_t index = 44 + hello.session_id_len;
    TEST_ASSERT_EQUAL_HEX16_MESSAGE((read_buf[index] << 8) +
				    read_buf[index + 1],
				    hello.cipher_suite,
				    "Server hello cipher suite was unmarshalled incorrectly");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(read_buf[index + 2],
				   hello.compression_method,
				   "Server hello compression method was unmarshalled incorrectly");

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(read_buf + 11, ctx->server_random,
				     32,
				     "The server hello server random is not being added to the TLS context");
    check_tls_handshake_hash(ctx, read_buf + 5,
			     (read_buf[3] << 8) + read_buf[4]);
}

TEST(server_hello, invalid_message)
{
    struct server_hello hello;
    read_buf[5] = 0x32;

    TEST_ASSERT_EQUAL_MESSAGE(0, server_hello_recv(ctx, &hello),
			      "Receive should fail when the message does not match the server hello format");
}

TEST_GROUP_RUNNER(server_hello)
{
    RUN_TEST_CASE(server_hello, receiving);
    RUN_TEST_CASE(server_hello, invalid_message);
}
