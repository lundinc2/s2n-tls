/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#pragma once

#include "tls/s2n_tls_parameters.h"

#define sig_alg_check(a, b)  do { if ( (a) != (b) ) { POSIX_BAIL(S2N_ERR_INVALID_SIGNATURE_ALGORITHM); } } while(0)

typedef enum {
    S2N_SIGNATURE_ANONYMOUS = TLS_SIGNATURE_ALGORITHM_ANONYMOUS,
    S2N_SIGNATURE_RSA = TLS_SIGNATURE_ALGORITHM_RSA,
    S2N_SIGNATURE_ECDSA = TLS_SIGNATURE_ALGORITHM_ECDSA,

    /* Use Private Range for RSA PSS */
    S2N_SIGNATURE_RSA_PSS_RSAE = TLS_SIGNATURE_ALGORITHM_PRIVATE,
    S2N_SIGNATURE_RSA_PSS_PSS,
    /* Don't add any signature algorithms below S2N_SIGNATURE_SENTINEL */
    S2N_SIGNATURE_SENTINEL
} s2n_signature_algorithm;
