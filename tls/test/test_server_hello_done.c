#include "test_helpers.h"
#include "unity.h"
#include "unity_fixture.h"

static struct tls_context *ctx;
static struct tls_connection_mock connection;

TEST_GROUP(server_hello_done);

TEST_SETUP(server_hello_done)
{
    uint8_t server_hello_done[] = {
	0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00
    };
    tls_connection_mock_init(&connection);
    ctx = tls_context_new((struct tls_connection *) &connection);
    if (!ctx)
	TEST_FAIL_MESSAGE("Failed to initialize TLS context");
    memcpy(read_buf, server_hello_done, sizeof(server_hello_done));
}

TEST_TEAR_DOWN(server_hello_done)
{
    tls_context_free(ctx);
}

TEST(server_hello_done, receiving)
{
    TEST_ASSERT_EQUAL_MESSAGE(1, server_hello_done_recv(ctx),
			      "A valid receive of a server hello done message should return 1");
    check_tls_handshake_hash(ctx, read_buf + 5, 4);
}

TEST(server_hello_done, invalid_message)
{
    read_buf[5] = 0x32;
    TEST_ASSERT_EQUAL_MESSAGE(0, server_hello_done_recv(ctx),
			      "An invalid receive of a server hello done message should return 0");
}

TEST_GROUP_RUNNER(server_hello_done)
{
    RUN_TEST_CASE(server_hello_done, receiving);
    RUN_TEST_CASE(server_hello_done, invalid_message);
}
