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



#define CK_PTR    *
#define NULL_PTR    0
#define CK_DEFINE_FUNCTION( returnType, name )             returnType name
#define CK_DECLARE_FUNCTION( returnType, name )            returnType name
#define CK_DECLARE_FUNCTION_POINTER( returnType, name )    returnType( CK_PTR name )
#define CK_CALLBACK_FUNCTION( returnType, name )           returnType( CK_PTR name )
#include "pkcs11.h"

struct s2n_async_pkey_op *pkey_op = NULL;

typedef int (async_handler)(struct s2n_connection *conn);

static int async_handler_fail(struct s2n_connection *conn)
{
    FAIL_MSG("async_handler_fail should never get invoked");
    return S2N_FAILURE;
}

struct host_verify_data {
    uint8_t callback_invoked;
    uint8_t allow;
};

static uint8_t verify_host_fn(const char *host_name, size_t host_name_len, void *data) {
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return verify_data->allow;
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
int pkcs11_sign( s2n_hash_algorithm hash_alg, 
                 const uint8_t * hash_buf, 
                 uint32_t hash_len, 
                 uint8_t * signature_buf, 
                 uint32_t * signature_buf_len_ptr )
{
    CK_FUNCTION_LIST_PTR functionList = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_ULONG slotCount = 0;
    CK_SLOT_ID * slotId = NULL;
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    
    POSIX_GUARD(C_GetFunctionList(&functionList));
    POSIX_GUARD_PTR(functionList);
    POSIX_GUARD(functionList->C_Initialize(NULL));

    POSIX_GUARD(functionList->C_GetSlotList(CK_TRUE,
                                              NULL,
                                              &slotCount));

    /* TODO Use S2N memory API. */
    slotId = malloc(sizeof(CK_SLOT_ID) * (slotCount));
    POSIX_GUARD_PTR(slotId);

    POSIX_GUARD(functionList->C_GetSlotList(CK_TRUE,
                                              slotId,
                                              &slotCount));

    /* For now take the first slot, but need a better mechanism to find the test slot. */
    POSIX_GUARD(functionList->C_OpenSession(slotId[ 1 ],
                                             CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                              NULL,
                                              NULL, 
                                              &session));
    CK_UTF8CHAR pin[] = "0000";
    POSIX_GUARD(functionList->C_Login(session,
                                        CKU_USER,
                                        pin,
                                        sizeof(pin)-1UL));
    CK_UTF8CHAR label[] = "mytoken1";
    CK_ULONG count = 0;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;

    CK_ATTRIBUTE template[ 2 ] = {
                                      { .type = CKA_LABEL, 
                                        .pValue = (CK_VOID_PTR) label, 
                                        .ulValueLen = sizeof(label)-1
                                      },
                                      { .type = CKA_CLASS,
                                        .pValue = &key_class,
                                        .ulValueLen = sizeof( CK_OBJECT_CLASS ),
                                      }
                                   };


    POSIX_GUARD(functionList->C_FindObjectsInit(session, template, sizeof(template) / sizeof(CK_ATTRIBUTE)));

    POSIX_GUARD(functionList->C_FindObjects(session,
                                             &handle,
                                             1UL,
                                             &count));

    POSIX_GUARD(functionList->C_FindObjectsFinal(session));
    EXPECT_TRUE(handle != CK_INVALID_HANDLE);
    EXPECT_TRUE(count != 0);

    CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0 };
    CK_BYTE signature[2048] = {0};
    CK_ULONG signatureLength = sizeof(signature);

    POSIX_GUARD(functionList->C_SignInit(session,
                                           &mechanism,
                                           handle));


    CK_BYTE temp_hash[2048] = {0};
    (void)memcpy(temp_hash, hash_buf, hash_len);
    POSIX_GUARD(functionList->C_Sign(session,
                                       temp_hash,
                                       hash_len,
                                       signature,
                                       &signatureLength));

    return 0;
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

    s2n_async_pkey_op_type type;
    EXPECT_SUCCESS(s2n_async_get_op_type(op, &type));

    if( type == S2N_ASYNC_SIGN )
    {
        /* Perform the op */
        EXPECT_SUCCESS(s2n_async_pkey_op_offload(op, pkcs11_sign));
    }
    else
    {
        /* Perform the op */
        EXPECT_SUCCESS(s2n_async_pkey_op_perform(op, pkey));
    }

    /* Test that op can't be applied inside the callback */
    EXPECT_FAILURE_WITH_ERRNO(s2n_async_pkey_op_apply(op, conn), S2N_ERR_ASYNC_APPLY_WHILE_INVOKING);

    /* Free the op */
    EXPECT_SUCCESS(s2n_async_pkey_op_free(op));

    return S2N_FAILURE;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_cert_chain_and_key *chain_and_key;
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE];

    POSIX_GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

    POSIX_GUARD_PTR(chain_and_key = s2n_cert_chain_and_key_new());
    POSIX_GUARD(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, NULL));

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
            struct host_verify_data verify_data = {.allow = 1, .callback_invoked = 0};
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(server_config, verify_host_fn, &verify_data));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(client_config, async_pkey_apply_in_callback));
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(client_config, verify_host_fn, &verify_data));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* Create connection */
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));
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
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    END_TEST();
    return 0;
}

