#include "test_helpers.h"
#include "tls_impl.h"
#include "unity_fixture.h"
#include "unity.h"
#include "test_helpers.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <openssl/hmac.h>


static struct tls_context *ctx;
static struct tls_connection_mock connection;
static struct rsa_premaster_secret premaster;


static void check_encryption(uint8_t *cipher, size_t count,
			     const struct tls_record *plain)
{
    uint8_t dec_result[count];
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
    int len;

    uint8_t hmac_data[plain->length + 13];
    uint8_t hmac[SHA256_DIGEST_LENGTH];


    TEST_ASSERT_NOT_NULL(dec_ctx);

    if (EVP_DecryptInit
	(dec_ctx, EVP_aes_128_cbc(), ctx->client_enc_key, cipher) != 1) {
	EVP_CIPHER_CTX_free(dec_ctx);
	TEST_FAIL_MESSAGE(ERR_error_string(ERR_get_error(), NULL));
    }

    EVP_CIPHER_CTX_set_padding(dec_ctx, 0);

    if (EVP_DecryptUpdate(dec_ctx, dec_result, &len, cipher + 16, count) !=
	1) {
	EVP_CIPHER_CTX_free(dec_ctx);
	TEST_FAIL_MESSAGE(ERR_error_string(ERR_get_error(), NULL));
    }

    if (EVP_DecryptFinal(dec_ctx, dec_result + len, &len) != 1) {
	EVP_CIPHER_CTX_free(dec_ctx);
	TEST_FAIL_MESSAGE(ERR_error_string(ERR_get_error(), NULL));
    }
    EVP_CIPHER_CTX_free(dec_ctx);

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(plain->fragment, dec_result,
				     plain->length,
				     "Decryption of the message does not match the plaintext");
    uint8_t padding_len = (plain->length + SHA256_DIGEST_LENGTH) % 16;
    padding_len = padding_len ? 16 - padding_len : 16;

    for (int i = 0; i < padding_len; ++i)
	TEST_ASSERT_EQUAL_HEX8_MESSAGE(padding_len - 1,
				       dec_result[count - i - 1],
				       "Wrong padding on the decrypted result");

    num_to_bytes(ctx->client_seq, hmac_data, 8);
    hmac_data[8] = plain->type;
    hmac_data[9] = plain->version.major;
    hmac_data[10] = plain->version.minor;
    num_to_bytes(plain->length, hmac_data + 11, 2);
    memcpy(hmac_data + 13, plain->fragment, plain->length);

    if (!HMAC
	(EVP_sha256(), ctx->client_mac_key, sizeof(ctx->client_mac_key),
	 hmac_data, sizeof(hmac_data), hmac, NULL))
	TEST_FAIL_MESSAGE(ERR_error_string(ERR_get_error(), NULL));

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(hmac, dec_result + plain->length,
				     sizeof(hmac),
				     "The HMAC code verification failed");
}


TEST_GROUP(tls_context);

TEST_SETUP(tls_context)
{
    tls_connection_mock_init(&connection);
    premaster_mock(&premaster);
    ctx = tls_context_new((struct tls_connection *) &connection);
    if (!ctx)
	TEST_FAIL_MESSAGE("Failed to initialize TLS context");
}

TEST_TEAR_DOWN(tls_context)
{
    tls_context_free(ctx);
}

TEST(tls_context, initialize)
{
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.major, ctx->version.major,
				   "The version should be TLS 1.2");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(tls_1_2.minor, ctx->version.minor,
				   "The version should be TLS 1.2");
    TEST_ASSERT_NOT_NULL_MESSAGE(ctx->handshake_hashing,
				 "The hashing of handshake messages is not intialized");
    TEST_ASSERT_NOT_NULL_MESSAGE(ctx->connection,
				 "The connection should point to the input connection object");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE((struct tls_connection_mock *)
				     ctx->connection, &connection,
				     sizeof(connection),
				     "The connection should point to the input connection object");
    TEST_ASSERT_EQUAL_MESSAGE(0x0, ctx->client_seq,
			      "The client sequence number should be set to 0");
    TEST_ASSERT_EQUAL_MESSAGE(0x0, ctx->server_seq,
			      "The server sequence number should be set to 0");
}

TEST(tls_context, send_no_record)
{
    uint8_t guard[10];
    RAND_bytes(guard, sizeof(guard));
    memcpy(write_buf, guard, sizeof(guard));
    TEST_ASSERT_EQUAL_MESSAGE(0, tls_context_send_record(ctx, NULL),
			      "Send should fail when no record is passed in");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(guard, write_buf, sizeof(guard),
				     "Nothing should be written when no records are provided");
}

TEST(tls_context, send_one_record)
{
    uint8_t data[] = { 0x1, 0x2 };

    struct tls_record record = {
	.type = handshake,
	.length = sizeof(data),
	.version = tls_1_2,
	.fragment = data
    };

    TEST_ASSERT_EQUAL_MESSAGE(1,
			      tls_context_send_record(ctx, &record, NULL),
			      "Failed to send records");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(record.type, write_buf[0],
				   "The record should start with the content type");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(record.version.major, write_buf[1],
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(record.version.minor, write_buf[2],
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(record.length,
				    (write_buf[3] << 8) + write_buf[4],
				    "The record should contain the length of the fragment");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(record.fragment, write_buf + 5,
				     record.length,
				     "Fragment is not being sent");
}

TEST(tls_context, send_multiple_records)
{
    uint8_t data[] = { 0x1, 0x2 };

    struct tls_record record1 = {
	.type = handshake,
	.length = sizeof(data),
	.version = tls_1_2,
	.fragment = data
    };

    struct tls_record record2 = {
	.type = change_cipher_spec,
	.length = sizeof(data),
	.version = tls_1_2,
	.fragment = data
    };

    TEST_ASSERT_EQUAL_MESSAGE(1,
			      tls_context_send_record(ctx, &record1,
						      &record2, NULL),
			      "Failed to send records");
    uint8_t *p = write_buf;
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(record1.type, *p,
				   "The record should start with the content type");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(record1.version.major, p[1],
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(record1.version.minor, p[2],
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(record1.length, (p[3] << 8) + p[4],
				    "The record should contain the length of the fragment");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(record1.fragment, p + 5,
				     record1.length,
				     "Fragment is not being sent");
    p += 5 + record1.length;
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(record2.type, *p,
				   "The record should start with the content type");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(record2.version.major, p[1],
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(record2.version.minor, p[2],
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(record2.length, (p[3] << 8) + p[4],
				    "The record should contain the length of the fragment");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(record2.fragment, p + 5,
				     record2.length,
				     "Fragment is not being sent");
}

TEST(tls_context, recv_record)
{
    uint8_t data[] = { 0x16, 0x3, 0x3, 0x0, 0x2, 0x15, 0x23 };
    struct tls_record record;

    memcpy(read_buf, data, sizeof(data));
    TEST_ASSERT_EQUAL_MESSAGE(1, tls_context_recv_record(ctx, &record),
			      "Failed to receive a record");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(data[0], record.type,
				   "The record should start with the content type");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(data[1], record.version.major,
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(data[2], record.version.minor,
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE((data[3] << 8) + data[4],
				    record.length,
				    "The record should contain the length of the fragment");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(data + 5, record.fragment,
				     record.length,
				     "Fragment is not being received");
    tls_record_free(&record);
}

TEST(tls_context, recv_multiple_records)
{
    uint8_t data[] = {
	0x16, 0x3, 0x3, 0x0, 0x2, 0x15, 0x23,
	0x14, 0x3, 0x3, 0x0, 0x4, 0x12, 0x11,
	0x15, 0x16
    };
    struct tls_record record;

    memcpy(read_buf, data, sizeof(data));
    uint8_t *p = data;

    TEST_ASSERT_EQUAL_MESSAGE(1, tls_context_recv_record(ctx, &record),
			      "Failed to receive a record");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(*p, record.type,
				   "The record should start with the content type");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(p[1], record.version.major,
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(p[2], record.version.minor,
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE((p[3] << 8) + p[4], record.length,
				    "The record should contain the length of the fragment");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(p + 5, record.fragment, record.length,
				     "Fragment is not being received");
    p += record.length + 5;
    tls_record_free(&record);

    TEST_ASSERT_EQUAL_MESSAGE(1, tls_context_recv_record(ctx, &record),
			      "Failed to receive a record");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(*p, record.type,
				   "The record should start with the content type");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(p[1], record.version.major,
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(p[2], record.version.minor,
				   "The record should contain the version");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE((p[3] << 8) + p[4], record.length,
				    "The record should contain the length of the fragment");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(p + 5, record.fragment, record.length,
				     "Fragment is not being received");
    tls_record_free(&record);
}

TEST(tls_context, handshake_hashing)
{
    uint8_t data[32];

    RAND_bytes(data, sizeof(data));
    TEST_ASSERT_EQUAL_MESSAGE(1,
			      tls_context_hash_handshake(ctx, data,
							 sizeof(data)),
			      "Failed to add message to hashing context");
    check_tls_handshake_hash(ctx, data, 32);
}

TEST(tls_context, handshake_update)
{
    uint8_t data[32];

    RAND_bytes(data, sizeof(data));

    TEST_ASSERT_EQUAL_MESSAGE(1, tls_context_hash_handshake(ctx, data, 16),
			      "Failed to add message to hashing context");
    TEST_ASSERT_EQUAL_MESSAGE(1,
			      tls_context_hash_handshake(ctx, data + 16,
							 16),
			      "Failed to add message to hashing context");
    check_tls_handshake_hash(ctx, data, 32);
}


TEST(tls_context, digest_call_no_output)
{
    uint8_t data[32];

    RAND_bytes(data, sizeof(data));
    TEST_ASSERT_EQUAL_MESSAGE(1,
			      tls_context_hash_handshake(ctx, data,
							 sizeof(data)),
			      "Failed to add message to hashing context");
    TEST_ASSERT_EQUAL_MESSAGE(SHA256_DIGEST_LENGTH,
			      tls_context_handshake_digest(ctx, NULL),
			      "The call to the digest function should return the length of the digest");
}


TEST(tls_context, multiple_digest_call)
{
    uint8_t data[32];
    uint8_t digest1[SHA256_DIGEST_LENGTH];
    uint8_t digest2[SHA256_DIGEST_LENGTH];

    RAND_bytes(data, sizeof(data));
    TEST_ASSERT_EQUAL_MESSAGE(1,
			      tls_context_hash_handshake(ctx, data,
							 sizeof(data)),
			      "Failed to add message to hashing context");
    TEST_ASSERT_EQUAL_MESSAGE(SHA256_DIGEST_LENGTH,
			      tls_context_handshake_digest(ctx, digest1),
			      "The call to the digest function should return the length of the digest");
    TEST_ASSERT_EQUAL_MESSAGE(SHA256_DIGEST_LENGTH,
			      tls_context_handshake_digest(ctx, digest2),
			      "The call to the digest function should return the length of the digest");

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(digest1, digest2,
				     SHA256_DIGEST_LENGTH,
				     "Multiple calls to the digest function should always return the same value");
}



TEST(tls_context, derive_keys)
{
    unsigned char expected_master[] = {
	0x98, 0x5D, 0x96, 0x37, 0xBB, 0xBD, 0x2E, 0xF7,
	0x3E, 0x6D, 0xBF, 0xC9, 0xEC, 0x70, 0x6D, 0x39,
	0x88, 0xE4, 0x4A, 0x8A, 0xED, 0x52, 0xC9, 0xDC,
	0xBD, 0x09, 0xE6, 0xBA, 0xE9, 0xD0, 0xE3, 0xE2,
	0xD8, 0x03, 0xA8, 0xD3, 0xC9, 0xD9, 0x1E, 0xCF,
	0x10, 0x10, 0xC0, 0xE7, 0x1A, 0x9F, 0x72, 0xDA
    };

    uint8_t key_block[] = {
	0x1b, 0x25, 0x85, 0x4f, 0x69, 0x14, 0x94, 0x47,
	0x65, 0xfe, 0xa9, 0x62, 0xa6, 0xd3, 0x7a, 0x8b,
	0x41, 0xc4, 0x41, 0x8b, 0x9d, 0x1c, 0x20, 0xf1,
	0x8f, 0x74, 0x2c, 0xc7, 0x32, 0x32, 0x82, 0x74,
	0x3d, 0x68, 0x5f, 0xa5, 0xca, 0x9b, 0xc1, 0xbc,
	0x67, 0xc7, 0xb4, 0x39, 0x08, 0x4a, 0xec, 0xad,
	0x24, 0x51, 0xd0, 0xad, 0x3f, 0x87, 0x60, 0x77,
	0x2d, 0x83, 0x4e, 0xbd, 0x9c, 0xb6, 0x43, 0x14,
	0xd8, 0x44, 0xa3, 0x7a, 0xe9, 0xb9, 0x14, 0x1b,
	0x01, 0xe4, 0x2f, 0x37, 0xa8, 0x41, 0x9d, 0xbd,
	0x45, 0x75, 0x87, 0xb8, 0xd5, 0xf2, 0x78, 0x2c,
	0x5f, 0x7a, 0x7d, 0x12, 0x3c, 0x57, 0x66, 0x84
    };

    tls_context_mock(ctx);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_master, ctx->master_secret,
				     sizeof(ctx->master_secret),
				     "The derivation of the master secret is wrong");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(key_block, ctx->client_mac_key, 32,
				     "The derivation of the client MAC key is wrong");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(key_block + 32, ctx->server_mac_key,
				     32,
				     "The derivation of the server MAC key is wrong");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(key_block + 64, ctx->client_enc_key,
				     16,
				     "The derivation of the client encryption key is wrong");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(key_block + 80, ctx->server_enc_key,
				     16,
				     "The derivation of the server encryption key is wrong");
}

TEST(tls_context, cipher_len)
{
    uint8_t plaintext[] = "testing\n";

    tls_context_mock(ctx);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");

    struct tls_record record = {
	.type = handshake,
	.version = tls_1_2,
	.length = sizeof(plaintext) - 1,
	.fragment = plaintext,
    };

    TEST_ASSERT_EQUAL_MESSAGE(64, tls_context_encrypt(ctx, &record, NULL),
			      "When called with no output it should return the length of the resulting ciphertext");
}

TEST(tls_context, single_text)
{
    uint8_t plaintext[] = "testing\n";
    size_t expected_len = 64;
    uint8_t cipher[expected_len];

    tls_context_mock(ctx);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");

    struct tls_record record = {
	.type = application_data,
	.version = tls_1_2,
	.length = sizeof(plaintext) - 1,
	.fragment = plaintext,
    };

    TEST_ASSERT_EQUAL_MESSAGE(expected_len,
			      tls_context_encrypt(ctx, &record, cipher),
			      "The encryption should return the length of the ciphertext");

    check_encryption(cipher, expected_len - 16, &record);
}

TEST(tls_context, plain_same_len_block)
{
    uint8_t plaintext[] = "aaaaaaaaaaaaaaaa";
    size_t expected_len = 80;
    uint8_t cipher[expected_len];

    tls_context_mock(ctx);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");

    struct tls_record record = {
	.type = application_data,
	.version = tls_1_2,
	.length = sizeof(plaintext) - 1,
	.fragment = plaintext,
    };

    TEST_ASSERT_EQUAL_MESSAGE(expected_len,
			      tls_context_encrypt(ctx, &record, cipher),
			      "The encryption should return the length of the ciphertext");
    check_encryption(cipher, expected_len - 16, &record);
}

TEST(tls_context, multiple_encryptions)
{
    uint8_t plaintext1[] = "testing\n";
    uint8_t plaintext2[] = "aaaaaaaaaaaaaaaa";
    uint8_t cipher[80];

    uint8_t expected_len = 64;

    tls_context_mock(ctx);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");

    struct tls_record record = {
	.type = application_data,
	.version = tls_1_2,
	.length = sizeof(plaintext1) - 1,
	.fragment = plaintext1,
    };

    TEST_ASSERT_EQUAL_MESSAGE(expected_len,
			      tls_context_encrypt(ctx, &record, cipher),
			      "The encryption should return the length of the ciphertext");
    check_encryption(cipher, expected_len - 16, &record);

    record.fragment = plaintext2;
    record.length = sizeof(plaintext2) - 1;
    expected_len = 80;

    TEST_ASSERT_EQUAL_MESSAGE(expected_len,
			      tls_context_encrypt(ctx, &record, cipher),
			      "The encryption should return the length of the ciphertext");
    check_encryption(cipher, expected_len - 16, &record);
}


TEST(tls_context, decrypt_plain_len)
{
    uint8_t cipher[] = {
	0x42, 0x66, 0xea,
	0xc6, 0xba, 0x75, 0x83, 0xe5, 0x80, 0xf1, 0xcc,
	0x32, 0xf1, 0xe5, 0x6e, 0x5c, 0x2b, 0x61, 0x42,
	0x88, 0x9d, 0x5a, 0x6b, 0xb4, 0x40, 0x88, 0x3d,
	0xf8, 0x85, 0x44, 0x5b, 0xaa, 0x40, 0x3b, 0x75,
	0x5e, 0xe3, 0x31, 0xad, 0x30, 0xcb, 0xd8, 0xb1,
	0x56, 0xb1, 0x2a, 0x88, 0x0b, 0xae, 0x75, 0x42,
	0xf2, 0x99, 0xc2, 0x72, 0xd1, 0xe6, 0x8d, 0xa8,
	0x5d, 0xac, 0xf2, 0xcf, 0xce
    };

    tls_context_mock(ctx);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");
    ctx->server_seq = 1;
    struct tls_record record = {
	.type = application_data,
	.version = tls_1_2,
	.length = sizeof(cipher),
	.fragment = cipher,
    };
    TEST_ASSERT_EQUAL_MESSAGE(5, tls_context_decrypt(ctx, &record, NULL),
			      "When called with no output it should return the length of the plaintext");
}


TEST(tls_context, decrypt_text)
{
    uint8_t cipher[] = {
	0x42, 0x66, 0xea, 0xc6, 0xba, 0x75, 0x83, 0xe5,
	0x80, 0xf1, 0xcc, 0x32, 0xf1, 0xe5, 0x6e, 0x5c,
	0x2b, 0x61, 0x42, 0x88, 0x9d, 0x5a, 0x6b, 0xb4,
	0x40, 0x88, 0x3d, 0xf8, 0x85, 0x44, 0x5b, 0xaa,
	0x40, 0x3b, 0x75, 0x5e, 0xe3, 0x31, 0xad, 0x30,
	0xcb, 0xd8, 0xb1, 0x56, 0xb1, 0x2a, 0x88, 0x0b, 0xae,
	0x75, 0x42, 0xf2, 0x99, 0xc2, 0x72, 0xd1, 0xe6, 0x8d, 0xa8,
	0x5d, 0xac, 0xf2, 0xcf, 0xce
    };
    uint8_t plain[16];
    tls_context_mock(ctx);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");
    ctx->server_seq = 1;
    struct tls_record record = {
	.type = application_data,
	.version = tls_1_2,
	.length = sizeof(cipher),
	.fragment = cipher,
    };
    TEST_ASSERT_EQUAL_MESSAGE(5, tls_context_decrypt(ctx, &record, plain),
			      "The decryption function should return the length of the ciphertext");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE("test\n", plain, 5,
				     "The decrypted text does not match the expected plain text");
}


TEST(tls_context, decrypt_tampered)
{
    uint8_t cipher[] = {
	0x42, 0x66, 0xea, 0xc6, 0xba, 0x75, 0x02, 0xe5,
	0x80, 0xf1, 0xcc, 0x32, 0xf1, 0xe5, 0x6e, 0x5c,
	0x2b, 0x61, 0x42,
	0x88, 0x9d, 0x5a, 0x6b, 0xb4, 0x40, 0x88, 0x3d,
	0xf8, 0x85, 0x44, 0x5b, 0xaa, 0x40, 0x3b, 0x75,
	0x5e, 0xe3, 0x31, 0xad, 0x30, 0xcb, 0xd8, 0xb1,
	0x56, 0xb1, 0x2a, 0x88, 0x0b, 0xae, 0x75, 0x42,
	0xf2, 0x99, 0xc2, 0x72, 0xd1, 0xe6, 0x8d, 0xa8,
	0x5d, 0xac, 0xf2, 0xcf, 0xce
    };
    tls_context_mock(ctx);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
				  tls_context_derive_keys(ctx, &premaster),
				  "Failed to derive keys");
    ctx->server_seq = 1;
    struct tls_record record = {
	.type = application_data,
	.version = tls_1_2,
	.length = sizeof(cipher),
	.fragment = cipher,
    };
    TEST_ASSERT_EQUAL_MESSAGE(0, tls_context_decrypt(ctx, &record, NULL),
			      "The decryption is not checking the validity of the HMAC code");
}


TEST_GROUP_RUNNER(tls_context)
{
    RUN_TEST_CASE(tls_context, initialize);
    RUN_TEST_CASE(tls_context, send_no_record);
    RUN_TEST_CASE(tls_context, send_one_record);
    RUN_TEST_CASE(tls_context, send_multiple_records);
    RUN_TEST_CASE(tls_context, recv_record);
    RUN_TEST_CASE(tls_context, recv_multiple_records);
    RUN_TEST_CASE(tls_context, handshake_hashing);
    RUN_TEST_CASE(tls_context, handshake_update);
    RUN_TEST_CASE(tls_context, digest_call_no_output);
    RUN_TEST_CASE(tls_context, multiple_digest_call);
    RUN_TEST_CASE(tls_context, derive_keys);
    RUN_TEST_CASE(tls_context, cipher_len);
    RUN_TEST_CASE(tls_context, single_text);
    RUN_TEST_CASE(tls_context, plain_same_len_block);
    RUN_TEST_CASE(tls_context, multiple_encryptions);
    RUN_TEST_CASE(tls_context, decrypt_plain_len);
    RUN_TEST_CASE(tls_context, decrypt_text);
    RUN_TEST_CASE(tls_context, decrypt_tampered);
}
