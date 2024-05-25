#include "tls_connection.h"
#include "unity.h"
#include "unity_fixture.h"
#include "test_helpers.h"
#include <errno.h>
#include <openssl/rand.h>

static struct tls_connection_mock connection;

TEST_GROUP(connection_read);

TEST_SETUP(connection_read)
{
    RAND_bytes(read_buf, 200);
    tls_connection_mock_init(&connection);
}

TEST_TEAR_DOWN(connection_read)
{
    failure = 0;
    interrupt_probability = 0;
    errno = 0;
}

TEST(connection_read, success)
{
    uint8_t buf[50];
    ssize_t res =
	tls_connection_read((struct tls_connection *) &connection, buf,
			    50);
    TEST_ASSERT_EQUAL(50, res);
}

TEST(connection_read, failure)
{
    failure = 1;
    uint8_t buf[50];
    ssize_t res =
	tls_connection_read((struct tls_connection *) &connection, buf,
			    50);
    TEST_ASSERT_EQUAL(-1, res);
}

TEST(connection_read, read_less)
{
    uint8_t buf[200];
    ssize_t res =
	tls_connection_read((struct tls_connection *) &connection, buf,
			    200);
    TEST_ASSERT_EQUAL(200, res);
    TEST_ASSERT_EQUAL_MEMORY(read_buf, buf, 200);
}

TEST(connection_read, interrupt)
{
    interrupt_probability = 0.9;
    uint8_t buf[200];
    ssize_t res =
	tls_connection_read((struct tls_connection *) &connection, buf,
			    200);
    TEST_ASSERT_EQUAL(200, res);
    TEST_ASSERT_EQUAL_MEMORY(read_buf, buf, 200);
}

TEST_GROUP_RUNNER(connection_read)
{
    RUN_TEST_CASE(connection_read, success);
    RUN_TEST_CASE(connection_read, failure);
    RUN_TEST_CASE(connection_read, read_less);
    RUN_TEST_CASE(connection_read, interrupt);
}
