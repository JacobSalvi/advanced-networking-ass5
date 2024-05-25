#include "tls_connection.h"
#include "unity.h"
#include "unity_fixture.h"
#include <errno.h>
#include <openssl/rand.h>
#include "test_helpers.h"

static struct tls_connection_mock connection;

TEST_GROUP(connection_write);

TEST_SETUP(connection_write)
{
    RAND_bytes(read_buf, 200);
    tls_connection_mock_init(&connection);
}

TEST_TEAR_DOWN(connection_write)
{
    failure = 0;
    interrupt_probability = 0;
    errno = 0;
}

TEST(connection_write, success)
{
    ssize_t res =
	tls_connection_write((struct tls_connection *) &connection,
			     read_buf, 50);
    TEST_ASSERT_EQUAL(50, res);
    TEST_ASSERT_EQUAL_MEMORY(read_buf, write_buf, 50);
}

TEST(connection_write, failure)
{
    failure = 1;
    ssize_t res =
	tls_connection_write((struct tls_connection *) &connection,
			     read_buf, 50);
    TEST_ASSERT_EQUAL(-1, res);
}

TEST(connection_write, write_less)
{
    ssize_t res =
	tls_connection_write((struct tls_connection *) &connection,
			     read_buf, 200);
    TEST_ASSERT_EQUAL(200, res);
    TEST_ASSERT_EQUAL_MEMORY(read_buf, write_buf, 200);
}

TEST(connection_write, interrupt)
{
    interrupt_probability = 0.9;
    ssize_t res =
	tls_connection_write((struct tls_connection *) &connection,
			     read_buf, 200);
    TEST_ASSERT_EQUAL(200, res);
    TEST_ASSERT_EQUAL_MEMORY(read_buf, write_buf, 200);
}

TEST_GROUP_RUNNER(connection_write)
{
    RUN_TEST_CASE(connection_write, success);
    RUN_TEST_CASE(connection_write, failure);
    RUN_TEST_CASE(connection_write, write_less);
    RUN_TEST_CASE(connection_write, interrupt);
}
