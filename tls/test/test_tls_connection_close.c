#include "tls_connection.h"
#include "unity.h"
#include "unity_fixture.h"
#include "test_helpers.h"

static struct tls_connection_mock connection;

TEST_GROUP(connection_close);

TEST_SETUP(connection_close)
{
    tls_connection_mock_init(&connection);
}

TEST_TEAR_DOWN(connection_close)
{
    failure = 0;
}

TEST(connection_close, success)
{
    TEST_ASSERT_EQUAL(0, tls_connection_close((struct tls_connection *)
					      &connection));
    TEST_ASSERT_EQUAL(1, connection.closed);
}

TEST(connection_close, failure)
{
    failure = 1;
    TEST_ASSERT_EQUAL(-1, tls_connection_close((struct tls_connection *)
					       &connection));
}

TEST_GROUP_RUNNER(connection_close)
{
    RUN_TEST_CASE(connection_close, success);
    RUN_TEST_CASE(connection_close, failure);
}
