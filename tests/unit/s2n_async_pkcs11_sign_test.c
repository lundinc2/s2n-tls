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

#include <pthread.h>

#define CK_PTR    *
#define NULL_PTR    0
#define CK_DEFINE_FUNCTION( returnType, name )             returnType name
#define CK_DECLARE_FUNCTION( returnType, name )            returnType name
#define CK_DECLARE_FUNCTION_POINTER( returnType, name )    returnType( CK_PTR name )
#define CK_CALLBACK_FUNCTION( returnType, name )           returnType( CK_PTR name )

/* Used to add SHA256 ASN1 encoding to the PKCS #11 RSA signature. */
#define pkcs11STUFF_APPENDED_TO_RSA_SIG    { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 }

#include "pkcs11.h"

struct s2n_async_pkey_op *pkey_op = NULL;
static pthread_mutex_t pkcs11_mutex = {0};

struct host_verify_data {
    uint8_t callback_invoked;
    uint8_t allow;
};

static uint8_t verify_host_fn(const char *host_name, size_t host_name_len, void *data) {
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return verify_data->allow;
}

CK_RV append_sha256_id( const uint8_t * sha256_hash,
                                                uint8_t * hash_oid_buf )
{
    POSIX_GUARD_PTR(sha256_hash);
    POSIX_GUARD_PTR(hash_oid_buf);

    const uint8_t oid_sequence[] = pkcs11STUFF_APPENDED_TO_RSA_SIG;

    ( void ) memcpy( hash_oid_buf, oid_sequence, sizeof( oid_sequence ) );
    ( void ) memcpy( &hash_oid_buf[ sizeof( oid_sequence ) ], sha256_hash, 32 );

    return CKR_OK;
}

static int pkcs11_decrypt(const uint8_t * in, 
                 uint32_t in_len,
                 uint8_t ** out_buf, 
                 uint32_t * out_len)
{
    CK_FUNCTION_LIST_PTR functionList = NULL;
    POSIX_GUARD(C_GetFunctionList(&functionList));
    POSIX_GUARD_PTR(functionList);
    POSIX_GUARD(functionList->C_Initialize(NULL));

    CK_ULONG slotCount = 0;
    POSIX_GUARD(functionList->C_GetSlotList(CK_TRUE,
                                              NULL,
                                              &slotCount));

    CK_SLOT_ID * slotId = malloc(sizeof(CK_SLOT_ID) * (slotCount));
    POSIX_GUARD_PTR(slotId);

    POSIX_GUARD(functionList->C_GetSlotList(CK_TRUE,
                                              slotId,
                                              &slotCount));
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    POSIX_GUARD(functionList->C_OpenSession(slotId[2],
                                             CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                              NULL,
                                              NULL, 
                                              &session));
    CK_UTF8CHAR pin[] = "0000";
    POSIX_GUARD(functionList->C_Login(session,
                                        CKU_USER,
                                        pin,
                                        sizeof(pin)-1UL));
    CK_UTF8CHAR label[] = "rsa-privkey";
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

    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    POSIX_GUARD(functionList->C_FindObjects(session,
                                             &handle,
                                             1UL,
                                             &count));

    POSIX_GUARD(functionList->C_FindObjectsFinal(session));
    EXPECT_TRUE(handle != CK_INVALID_HANDLE);
    EXPECT_TRUE(count != 0);


    CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0 };

    POSIX_GUARD(functionList->C_DecryptInit(session,
                                           &mechanism,
                                           handle));


    POSIX_GUARD(functionList->C_Decrypt(session,
                                       in,
                                       in_len,
                                       NULL,
                                       out_len));

    uint8_t * decrypted = malloc(*out_len);
    POSIX_GUARD_PTR(decrypted);
    POSIX_GUARD(functionList->C_Decrypt(session,
                                       in,
                                       in_len,
                                       decrypted,
                                       out_len));
    *out_buf = decrypted;

    free(slotId);
    POSIX_GUARD(functionList->C_CloseSession(session));
    /* For some reason finalize crashes. */
    /* POSIX_GUARD(functionList->C_Finalize(NULL)); */

    return S2N_SUCCESS;
}

static int pkcs11_sign(const uint8_t * hash_buf, 
                 uint32_t hash_len,
                 uint8_t ** sig_buf, 
                 uint32_t * sig_len)
{
    /* OpenSSL expects hashed data without padding, but PKCS #11 C_Sign function performs a hash
     * & sign if hash algorithm is specified.  This helper function applies padding
     * indicating data was hashed with SHA-256 while still allowing pre-hashed data to
     * be provided. */
    uint8_t sha256_encoding[] = pkcs11STUFF_APPENDED_TO_RSA_SIG;
    uint32_t temp_digest_len = hash_len + sizeof(sha256_encoding);
    uint8_t * temp_digest = malloc(temp_digest_len);
    append_sha256_id( hash_buf, temp_digest );

    CK_FUNCTION_LIST_PTR functionList = NULL;
    POSIX_GUARD(C_GetFunctionList(&functionList));
    POSIX_GUARD_PTR(functionList);
    POSIX_GUARD(functionList->C_Initialize(NULL));

    CK_ULONG slotCount = 0;
    POSIX_GUARD(functionList->C_GetSlotList(CK_TRUE,
                                              NULL,
                                              &slotCount));

    CK_SLOT_ID * slotId = malloc(sizeof(CK_SLOT_ID) * (slotCount));
    POSIX_GUARD_PTR(slotId);

    POSIX_GUARD(functionList->C_GetSlotList(CK_TRUE,
                                              slotId,
                                              &slotCount));
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    POSIX_GUARD(functionList->C_OpenSession(slotId[2],
                                             CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                              NULL,
                                              NULL, 
                                              &session));
    CK_UTF8CHAR pin[] = "0000";
    POSIX_GUARD(functionList->C_Login(session,
                                        CKU_USER,
                                        pin,
                                        sizeof(pin)-1UL));
    CK_UTF8CHAR label[] = "rsa-privkey";
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

    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    POSIX_GUARD(functionList->C_FindObjects(session,
                                             &handle,
                                             1UL,
                                             &count));

    POSIX_GUARD(functionList->C_FindObjectsFinal(session));
    EXPECT_TRUE(handle != CK_INVALID_HANDLE);
    EXPECT_TRUE(count != 0);


    CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0 };

    POSIX_GUARD(functionList->C_SignInit(session,
                                           &mechanism,
                                           handle));


    POSIX_GUARD(functionList->C_Sign(session,
                                       temp_digest,
                                       temp_digest_len,
                                       NULL,
                                       sig_len));

    uint8_t * sig = malloc(*sig_len);
    POSIX_GUARD_PTR(sig);
    POSIX_GUARD(functionList->C_Sign(session,
                                       temp_digest,
                                       temp_digest_len,
                                       sig,
                                       sig_len));
   *sig_buf = sig;

    POSIX_GUARD(functionList->C_CloseSession(session));
    //POSIX_GUARD(functionList->C_Finalize(NULL));

    return 0;
}
struct task_params {
    struct s2n_connection *conn;
    struct s2n_async_pkey_op *op;
}task_params;

void * pkey_task(void * params)
{
    struct task_params * info = (struct task_params *) params;
    struct s2n_connection *conn = info->conn;
    struct s2n_async_pkey_op *op = info->op;
    uint32_t input_len;
    s2n_async_pkey_op_get_input_size(op, &input_len );
    uint8_t * input = malloc(input_len);
    
    s2n_async_pkey_op_get_input(op, input,input_len );

    uint8_t * output = NULL;
    uint32_t output_len = 0;

    s2n_async_pkey_op_type type;
    s2n_async_get_op_type(op, &type);

    
    pthread_mutex_lock(&pkcs11_mutex);
    if(type == S2N_ASYNC_DECRYPT)
    {
        pkcs11_decrypt(input, input_len, &output, &output_len);
    }
    else
    {
        pkcs11_sign(input, input_len, &output, &output_len);
    }
    pthread_mutex_unlock(&pkcs11_mutex);

    s2n_async_pkey_copy_output(op, output, output_len );
    free(output);

    s2n_async_pkey_op_apply(op, conn);
    
    free(params);
    pthread_exit(NULL);
}

int async_pkey_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    /* Check that we have op */
    EXPECT_NOT_NULL(op);
    pthread_t worker;
    struct task_params * params = malloc(sizeof(struct task_params));
    params->conn = conn; 
    params->op = op; 
    POSIX_GUARD(pthread_create(&worker, NULL, &pkey_task, params));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_cert_chain_and_key *chain_and_key;
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];

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
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_callback));
            server_config->security_policy = &server_security_policy;

            struct host_verify_data verify_data = {.allow = 1, .callback_invoked = 0};
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(server_config, verify_host_fn, &verify_data));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(client_config, async_pkey_callback));
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

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

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

