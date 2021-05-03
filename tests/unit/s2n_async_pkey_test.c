/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <s2n.h>

#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_async_pkey.h"

struct s2n_async_pkey_op *pkey_op = NULL;

uint8_t test_digest_data[] = "I hashed this";
const uint32_t test_digest_size = sizeof(test_digest_data);
const uint8_t test_signature_data[] = "I signed this";
const uint32_t test_signature_size = sizeof(test_signature_data);
uint8_t test_encrypted_data[] = "I encrypted this";
const uint32_t test_encrypted_size = sizeof(test_encrypted_data);
uint8_t test_decrypted_data[] = "I decrypted this";
const uint32_t test_decrypted_size = sizeof(test_decrypted_data);

typedef int (async_handler)(struct s2n_connection *conn);

static int async_handler_fail(struct s2n_connection *conn)
{
    FAIL_MSG("async_handler_fail should never get invoked");
    return S2N_FAILURE;
}

static int async_handler_wipe_connection_and_apply(struct s2n_connection *conn)
{
    /* Check that we have pkey_op */
    EXPECT_NOT_NULL(pkey_op);

    /* Extract pkey */
    struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(conn);
    EXPECT_NOT_NULL(chain_and_key);

    s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
    EXPECT_NOT_NULL(pkey);

    /* Wipe connection */
    EXPECT_SUCCESS(s2n_connection_wipe(conn));

    /* Test that we can perform pkey operation, even if original connection was wiped */
    EXPECT_SUCCESS(s2n_async_pkey_op_perform(pkey_op, pkey));

    /* Test that pkey op can't be applied to wiped connection */
    EXPECT_FAILURE_WITH_ERRNO(s2n_async_pkey_op_apply(pkey_op, conn), S2N_ERR_ASYNC_WRONG_CONNECTION);

    /* Free the pkey op */
    EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
    pkey_op = NULL;

    return S2N_FAILURE;
}

static int async_handler_free_pkey_op(struct s2n_connection *conn)
{
    static int function_entered = 0;

    /* Return failure on the second entrance into function so that we drop from try_handshake */
    if (function_entered++ % 2 == 1) {
        return S2N_FAILURE;
    }

    /* Check that we have pkey_op */
    EXPECT_NOT_NULL(pkey_op);

    /* Free the pkey op */
    EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
    pkey_op = NULL;

    /* Return success so that try_handshake calls s2n_negotiate again */
    return S2N_SUCCESS;
}

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn, async_handler handler)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
            return S2N_FAILURE;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
            return S2N_FAILURE;
        }

        if (server_blocked == S2N_BLOCKED_ON_APPLICATION_INPUT) {
            POSIX_GUARD(handler(server_conn));
        }

        EXPECT_NOT_EQUAL(++tries, 5);
    } while (client_blocked || server_blocked);

    POSIX_GUARD(s2n_shutdown_test_server_and_client(server_conn, client_conn));

    return S2N_SUCCESS;
}

int async_pkey_apply_in_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    /* Check that we have op */
    EXPECT_NOT_NULL(op);

    /* Extract pkey */
    struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(conn);
    EXPECT_NOT_NULL(chain_and_key);

    s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
    EXPECT_NOT_NULL(pkey);

    /* Perform the op */
    EXPECT_SUCCESS(s2n_async_pkey_op_perform(op, pkey));

    /* Test that op can't be applied inside the callback */
    EXPECT_FAILURE_WITH_ERRNO(s2n_async_pkey_op_apply(op, conn), S2N_ERR_ASYNC_APPLY_WHILE_INVOKING);

    /* Free the op */
    EXPECT_SUCCESS(s2n_async_pkey_op_free(op));

    return S2N_FAILURE;
}

int async_pkey_store_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;
    return S2N_SUCCESS;
}

int async_pkey_signature_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;

    s2n_async_pkey_op_type type = { 0 };
    EXPECT_SUCCESS(s2n_async_pkey_op_get_op_type(op, &type));
    EXPECT_EQUAL(type, S2N_ASYNC_SIGN);

    uint8_t expected_size = 0;
    EXPECT_SUCCESS(s2n_hash_digest_size(S2N_HASH_SHA1, &expected_size));

    uint32_t input_size = 0;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input_size(op, &input_size));
    EXPECT_EQUAL(input_size, expected_size);

    struct s2n_blob input = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&input, input_size));

    struct s2n_blob expected_digest = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&expected_digest, expected_size));

    struct s2n_hash_state digest = { 0 };
    EXPECT_SUCCESS(s2n_hash_new(&digest));
    EXPECT_SUCCESS(s2n_hash_init(&digest, S2N_HASH_SHA1));
    EXPECT_SUCCESS(s2n_hash_update(&digest, test_digest_data, test_digest_size));
    EXPECT_SUCCESS(s2n_hash_digest(&digest, expected_digest.data, expected_digest.size));
    EXPECT_SUCCESS(s2n_hash_free(&digest));

    EXPECT_SUCCESS(s2n_async_pkey_op_get_input(op, input.data, input.size));
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input(op, input.data, input.size));

    EXPECT_BYTEARRAY_EQUAL(input.data, expected_digest.data, expected_digest.size);
    EXPECT_SUCCESS(s2n_free(&input));
    EXPECT_SUCCESS(s2n_free(&expected_digest));

    EXPECT_SUCCESS(s2n_async_pkey_op_set_output(op, test_signature_data, test_signature_size));

    return S2N_SUCCESS;
}

int async_pkey_decrypt_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;

    s2n_async_pkey_op_type type = { 0 };
    EXPECT_SUCCESS(s2n_async_pkey_op_get_op_type(op, &type));
    EXPECT_EQUAL(type, S2N_ASYNC_DECRYPT);

    uint32_t input_size = 0;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input_size(op, &input_size));
    EXPECT_EQUAL(input_size, test_encrypted_size);

    struct s2n_blob input_buffer = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&input_buffer, input_size));

    EXPECT_SUCCESS(s2n_async_pkey_op_get_input(op, input_buffer.data, input_buffer.size));
    EXPECT_BYTEARRAY_EQUAL(input_buffer.data, test_encrypted_data, test_encrypted_size);
    EXPECT_SUCCESS(s2n_free(&input_buffer));

    EXPECT_SUCCESS(s2n_async_pkey_op_set_output(op, test_decrypted_data, test_decrypted_size));

    return S2N_SUCCESS;
}

int s2n_async_sign_complete(struct s2n_connection *conn, struct s2n_blob *signature)
{
    EXPECT_NOT_NULL(conn);
    EXPECT_NOT_NULL(signature);

    EXPECT_EQUAL(signature->size, test_signature_size);
    EXPECT_BYTEARRAY_EQUAL(signature->data, test_signature_data, test_signature_size);

    return S2N_SUCCESS;
}

int s2n_async_decrypt_complete(struct s2n_connection *conn, bool rsa_failed, struct s2n_blob *decrypted)
{
    EXPECT_NOT_NULL(conn);
    EXPECT_NOT_NULL(decrypted);
    EXPECT_FALSE(rsa_failed);

    EXPECT_EQUAL(decrypted->size, test_decrypted_size);
    EXPECT_BYTEARRAY_EQUAL(decrypted->data, test_decrypted_data, test_decrypted_size);

    return S2N_SUCCESS;
}

int async_pkey_invalid_input_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;

    EXPECT_FAILURE(s2n_async_pkey_op_get_op_type(op, NULL));
    EXPECT_FAILURE(s2n_async_pkey_op_get_input_size(op, NULL));
    EXPECT_FAILURE(s2n_async_pkey_op_get_input(op, NULL, 0));

    uint32_t input_size = 0;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input_size(op, &input_size));

    uint8_t placeholder_buffer[] = { 0x0, 0x0, 0x0, 0x0 };

    /* Buffer too small to contain data. */
    EXPECT_FAILURE(s2n_async_pkey_op_get_input(op, placeholder_buffer, input_size-1));

    EXPECT_FAILURE(s2n_async_pkey_op_set_output(op, NULL, test_signature_size));

    return S2N_FAILURE;
}

int async_pkey_invalid_complete(struct s2n_connection *conn, struct s2n_blob *signature)
{
    /* This function should never be called. If this does get called that means the completion function was called even
     * though there were issues with the callback. See async_pkey_invalid_input_callback. */
    FAIL();
    return S2N_FAILURE;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_cert_chain_and_key *chain_and_key;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Run all tests for 2 cipher suites to test both sign and decrypt operations */
    struct s2n_cipher_suite *test_cipher_suites[] = {
        &s2n_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    };

    for(int i=0; i < sizeof(test_cipher_suites)/sizeof(test_cipher_suites[0]); i++) {
        struct s2n_cipher_preferences server_cipher_preferences = {
            .count = 1,
            .suites = &test_cipher_suites[i],
        };

        struct s2n_security_policy server_security_policy = {
            .minimum_protocol_version = S2N_TLS12,
            .cipher_preferences = &server_cipher_preferences,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        EXPECT_TRUE(test_cipher_suites[i]->available);

        TEST_DEBUG_PRINT("Testing %s\n", test_cipher_suites[i]->name);

        /*  Test: apply while invoking callback */
        {
            struct s2n_config *server_config, *client_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_apply_in_callback));
            server_config->security_policy = &server_security_policy;

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* Create connection */
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Create nonblocking pipes */
            struct s2n_test_io_pair io_pair;
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_FAILURE_WITH_ERRNO(
                    try_handshake(server_conn, client_conn, async_handler_fail), S2N_ERR_ASYNC_CALLBACK_FAILED);

            /* Free the data */
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        }

        /*  Test: wipe connection and then perform and apply pkey op */
        {
            struct s2n_config *server_config, *client_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_store_callback));
            server_config->security_policy = &server_security_policy;

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* Create connection */
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Create nonblocking pipes */
            struct s2n_test_io_pair io_pair;
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_EQUAL(try_handshake(server_conn, client_conn, async_handler_wipe_connection_and_apply), S2N_FAILURE);

            /* Free the data */
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        }

        /*  Test: free the pkey op and try s2n_negotiate again */
        {
            struct s2n_config *server_config, *client_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_store_callback));
            server_config->security_policy = &server_security_policy;

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* Create connection */
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Create nonblocking pipes */
            struct s2n_test_io_pair io_pair;
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_FAILURE_WITH_ERRNO(
                    try_handshake(server_conn, client_conn, async_handler_free_pkey_op), S2N_ERR_ASYNC_BLOCKED);

            /* Free the data */
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        }
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    struct s2n_hash_state digest = { 0 };
    EXPECT_SUCCESS(s2n_hash_new(&digest));
    EXPECT_SUCCESS(s2n_hash_init(&digest, S2N_HASH_SHA1));
    EXPECT_SUCCESS(s2n_hash_update(&digest, test_digest_data, test_digest_size));

    /* Test: signature offload. */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        conn->config->async_pkey_cb = async_pkey_signature_callback;

        EXPECT_FALSE(s2n_result_is_ok(s2n_async_pkey_sign(conn, S2N_SIGNATURE_ECDSA, &digest, s2n_async_sign_complete)));
        EXPECT_TRUE(s2n_errno == S2N_ERR_ASYNC_BLOCKED);

        EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, conn));
        EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: decrypt offload. */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        conn->config->async_pkey_cb = async_pkey_decrypt_callback;

        struct s2n_blob encrypted_data = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&encrypted_data, test_encrypted_data, test_encrypted_size));

        struct s2n_blob decrypted_data = { 0 };
        /* Re-use the encrypted data buffer to make sure that the data was actually transformed in the callback. 
         * If we filled this with the decrypted data, we would not know if the decryption happened in the callback. */
        EXPECT_SUCCESS(s2n_blob_init(&decrypted_data, test_encrypted_data, test_encrypted_size));

        EXPECT_FALSE(s2n_result_is_ok(s2n_async_pkey_decrypt(conn, &encrypted_data, &decrypted_data, s2n_async_decrypt_complete)));
        EXPECT_TRUE(s2n_errno == S2N_ERR_ASYNC_BLOCKED);

        EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, conn));
        EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: errors in callback. */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        conn->config->async_pkey_cb = async_pkey_invalid_input_callback;

        EXPECT_FALSE(s2n_result_is_ok(s2n_async_pkey_sign(conn, S2N_SIGNATURE_ECDSA, &digest, async_pkey_invalid_complete)));
        EXPECT_TRUE(s2n_errno == S2N_ERR_ASYNC_CALLBACK_FAILED);

        EXPECT_FAILURE(s2n_async_pkey_op_apply(pkey_op, conn));
        EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    EXPECT_SUCCESS(s2n_hash_free(&digest));

    END_TEST();
    return 0;
}
