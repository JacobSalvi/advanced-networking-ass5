#include "unity_fixture.h"

static void run_tests(void)
{
    RUN_TEST_GROUP(connection_write);
    RUN_TEST_GROUP(connection_read);
    RUN_TEST_GROUP(connection_close);
    RUN_TEST_GROUP(tls_utilities);
    RUN_TEST_GROUP(tls_context);
    RUN_TEST_GROUP(client_hello);
    RUN_TEST_GROUP(server_hello);
    RUN_TEST_GROUP(server_certificate);
    RUN_TEST_GROUP(server_hello_done);
    RUN_TEST_GROUP(key_agreement);
}

int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, run_tests);
}
