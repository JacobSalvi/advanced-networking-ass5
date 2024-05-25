#include "tls_impl.h"
#include "unity_fixture.h"
#include "unity.h"

TEST_GROUP(tls_utilities);
TEST_SETUP(tls_utilities)
{
}

TEST_TEAR_DOWN(tls_utilities)
{
}

TEST(tls_utilities, num_to_bytes_all_zeros)
{
    uint8_t output[1];
    uint8_t expected[1] = { 0x0 };
    num_to_bytes(0, output, 1);

    TEST_ASSERT_EQUAL_MEMORY(expected, output, 1);
}

TEST(tls_utilities, num_to_bytes_single_byte)
{
    uint8_t output[3];
    uint8_t expected[3] = { 0x0, 0x0, 0x59 };
    num_to_bytes(0x59, output, 3);

    TEST_ASSERT_EQUAL_MEMORY(expected, output, 3);
}

TEST(tls_utilities, num_to_bytes_multiple_bytes)
{
    uint8_t output[6];
    uint8_t expected[6] = { 0x0, 0x0, 0x59, 0x31, 0x32, 0x03 };
    num_to_bytes(0x59313203, output, 6);

    TEST_ASSERT_EQUAL_MEMORY(expected, output, 6);
}

TEST(tls_utilities, num_to_bytes_shorter_output)
{
    uint8_t output[2];
    uint8_t expected[2] = { 0x32, 0x03 };
    num_to_bytes(0x59313203, output, 2);

    TEST_ASSERT_EQUAL_MEMORY(expected, output, 2);
}


TEST(tls_utilities, prf)
{
    uint8_t secret[] = "secret";
    uint8_t seed[] = "seed";
    uint8_t expected[] = {
	0x8e, 0x4d, 0x93, 0x25, 0x30, 0xd7, 0x65, 0xa0,
	0xaa, 0xe9, 0x74, 0xc3, 0x04, 0x73, 0x5e, 0xcc,
	0x12, 0x02, 0xa8, 0x19, 0xf8, 0x0a, 0xdb, 0xd5,
	0xad, 0x09, 0xc1, 0xa3, 0x4f, 0xc0, 0x69, 0x18,
	0xe3, 0xd0, 0x77, 0x95, 0x21, 0x4d, 0x94, 0xc6,
	0xa1, 0x97, 0x6c, 0xae, 0xa5, 0xa0, 0xb6, 0x44
    };
    uint8_t result[sizeof(expected)];

    TEST_ASSERT_EQUAL_MESSAGE(1,
			      tls_prf(secret, sizeof(secret) - 1, seed,
				      sizeof(seed) - 1, result,
				      sizeof(result)),
			      "The call to TLS PRF failed");
    TEST_ASSERT_EQUAL_MEMORY(expected, result, sizeof(result));
}

TEST_GROUP_RUNNER(tls_utilities)
{
    RUN_TEST_CASE(tls_utilities, num_to_bytes_all_zeros);
    RUN_TEST_CASE(tls_utilities, num_to_bytes_single_byte);
    RUN_TEST_CASE(tls_utilities, num_to_bytes_multiple_bytes);
    RUN_TEST_CASE(tls_utilities, num_to_bytes_shorter_output);
    RUN_TEST_CASE(tls_utilities, prf);
}
