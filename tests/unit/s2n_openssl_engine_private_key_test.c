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
#include <openssl/engine.h>

/* Test config. */
#define pkcs11_test_slot 2
#define pkcs11_pin "0000"
#define pkcs11_module_path "/usr/local/lib/softhsm/libsofthsm2.so"
#define pkcs11_rsa_key_uri "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=33c20f7957a34f66;token=mytoken2;object=rsa-privkey"
#define pkcs11_ec_key_uri  "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=33c20f7957a34f66;token=mytoken2;object=ecdsa-privkey"

struct s2n_async_pkey_op *pkey_op = NULL;
static pthread_mutex_t pkcs11_mutex = {0};
static ENGINE *e = NULL;

struct task_params {
    struct s2n_connection *conn;
    struct s2n_async_pkey_op *op;
};

static uint8_t verify_host_fn(const char *host_name, size_t host_name_len, void *data) {
    return 1;
}

static int pkcs11_decrypt(const char * pkcs11_uri,
                 const uint8_t * in, 
                 uint32_t in_len,
                 uint8_t ** out_buf, 
                 uint32_t * out_len)
{
    EVP_PKEY* pkey = ENGINE_load_private_key( e, pkcs11_uri, NULL, NULL );
    POSIX_GUARD_PTR(pkey);
    EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(pkey, e);
    POSIX_GUARD_PTR(ctx);

    POSIX_GUARD(EVP_PKEY_decrypt_init(ctx));

    POSIX_GUARD(EVP_PKEY_decrypt(ctx, NULL, out_len, in, in_len));
    uint8_t * out = malloc(*out_len);
    POSIX_GUARD(EVP_PKEY_decrypt(ctx, out, out_len, in, in_len));
    *out_buf = out;
    EVP_PKEY_CTX_free(ctx);

    return S2N_SUCCESS;
}

static int pkcs11_sign(const char * pkcs11_uri,
                 uint8_t * hash_buf, 
                 uint32_t hash_len,
                 uint8_t ** sig_buf, 
                 uint32_t * sig_len)
{
    EVP_PKEY* pkey = ENGINE_load_private_key( e, pkcs11_uri, NULL, NULL );
    POSIX_GUARD_PTR(pkey);
    EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(pkey, e);
    POSIX_GUARD_PTR(ctx);

    POSIX_GUARD(EVP_PKEY_sign_init(ctx));
    if(strstr(pkcs11_uri, "rsa"))
    {
        POSIX_GUARD(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING));
    } 
    POSIX_GUARD(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()));

    POSIX_GUARD(EVP_PKEY_sign(ctx, NULL, sig_len, hash_buf, hash_len));
    uint8_t * sig = malloc(*sig_len);
    POSIX_GUARD(EVP_PKEY_sign(ctx, sig, sig_len, hash_buf, hash_len));
    *sig_buf = sig;
    EVP_PKEY_CTX_free(ctx);
    
    return 0;
}

void * pkey_task(void * params)
{
    struct task_params * info = (struct task_params *) params;

    struct s2n_connection *conn = info->conn;
    struct s2n_async_pkey_op *op = info->op;

    uint32_t input_len;
    s2n_async_pkey_op_get_input_size(op, &input_len);
    uint8_t * input = malloc(input_len);

    s2n_async_pkey_op_get_input(op, input,input_len);

    uint8_t * output = NULL;
    uint32_t output_len = 0;

    s2n_async_pkey_op_type type;
    s2n_async_get_op_type(op, &type);

    struct s2n_cert_chain_and_key * cert_key = s2n_connection_get_selected_cert(conn);
    char * uri = s2n_cert_chain_and_key_get_ctx(cert_key);

    pthread_mutex_lock(&pkcs11_mutex);
    if(type == S2N_ASYNC_DECRYPT)
    {
        pkcs11_decrypt(uri, input, input_len, &output, &output_len);
    }
    else
    {
        pkcs11_sign(uri, input, input_len, &output, &output_len);
    }
    pthread_mutex_unlock(&pkcs11_mutex);

    s2n_async_pkey_copy_output(op, output, output_len);
    free(output);

    s2n_async_pkey_op_apply(op, conn);
    
    free(params);
    pthread_exit(NULL);
}

int async_pkey_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
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


    ENGINE_load_builtin_engines();
    e = ENGINE_by_id( "pkcs11" );
    POSIX_GUARD_PTR(e);
    ENGINE_ctrl_cmd_string( e, "MODULE_PATH", pkcs11_module_path, 0 );
    ENGINE_ctrl_cmd_string( e, "PIN", pkcs11_pin, 0 );
    ENGINE_init( e );

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_cert_chain_and_key *rsa_chain_and_key;
    struct s2n_cert_chain_and_key *ecdsa_chain_and_key;
    char rsa_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char ecdsa_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];

    POSIX_GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, rsa_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD(s2n_read_test_pem(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, ecdsa_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

    POSIX_GUARD_PTR(rsa_chain_and_key = s2n_cert_chain_and_key_new());
    POSIX_GUARD_PTR(ecdsa_chain_and_key = s2n_cert_chain_and_key_new());
    POSIX_GUARD(s2n_cert_chain_load_pem(rsa_chain_and_key, rsa_cert_chain_pem));
    POSIX_GUARD(s2n_cert_chain_load_pem(ecdsa_chain_and_key, ecdsa_cert_chain_pem));

    POSIX_GUARD(s2n_cert_chain_and_key_set_ctx(rsa_chain_and_key, pkcs11_rsa_key_uri));
    POSIX_GUARD(s2n_cert_chain_and_key_set_ctx(ecdsa_chain_and_key, pkcs11_ec_key_uri));

    struct s2n_cipher_suite *test_cipher_suites[] = {
        &s2n_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
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

        /*  Test: RSA/ECDSA */
        {
            struct s2n_config *server_config, *client_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_callback));
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(server_config, verify_host_fn, NULL));
            server_config->security_policy = &server_security_policy;

            EXPECT_NOT_NULL(client_config = s2n_config_new());

            if(i >= 2) {
                EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, NULL));

                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20190214"));
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, ecdsa_chain_and_key));
                EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, NULL));
            } else {
                EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

                EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, rsa_chain_and_key));
            }
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(client_config, async_pkey_callback));
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(client_config, verify_host_fn, NULL));

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

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_chain_and_key));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_chain_and_key));

    END_TEST();
    return 0;
}

