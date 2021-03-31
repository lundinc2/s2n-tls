# PKCS #11 support in S2N
## What is PKCS #11?
[PKCS #11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html) is a standard for interfacing with [cryptographic devices](##Appendix_B:_Glossary).

Some example cryptographic devices are Secure Elements, Hardware Security Modules (HSM), or Trusted Platform Modules (TPM). 

Alongside the PKCS #11 specification, a collection of ANSI C header files are provided in order to define the interface libraries and applications should use. 
Using the PKCS #11 interface, S2N can support multiple Cryptoki (Name of the PKCS #11 API) implementations and cryptographic devices.

## Customer Story
By offloading cryptographic operations to a cryptographic device, particularly the storage of sensitive data (such as a private key), customers can follow security best 
practices. Cryptographic devices generally associated with PKCS #11 have hardened security features, and are much harder for attackers to acquire secrets from. A good example 
device is the [ATECC608A](https://www.microchip.com/wwwproducts/en/ATECC608A-TNGTLS) mentioned in the feature request [SIM](https://t.corp.amazon.com/P44705525/). I recommend reading the features of the device to get
a good idea of what features a cryptographic device has. In this case the two most important characteristics for S2N are:
1. The private key is burned onto the device, and can never be overwritten.
    1. Note that some configurations allow for importing a private key that is generated on a separate device, but this goes against the recommended security best practices.
1. The private key can NEVER leave the device. There is no way to read the value of the key into memory, so it can only be used with a "handle".
    1. See `CK_OBJECT_HANDLE` in PKCS #11 specification.
    1. See `CKA_EXTRACTABLE` and `CKA_SENSITIVE` object attributes.

Currently S2N needs to be able to directly read the private key, and store it in memory. This is a major blocker for using the ATECC608A since there is no way to read the private key off the board. It is also a much better security story to not read the private
key, in order to prevent leaking the private key in S2N.

## Minimum Viable Product
The major blocker for using PKCS #11 with S2N is S2N's reliance on parsing the private key and storing it in memory. All the other use cases for PKCS #11 are either nice to haves or non-blocking. An example of a nice to have would be to use PKCS #11 to verify a signature. For now a workaround for this example is to extract the public key from the cryptographic device beforehand, and provide S2N a PEM file to parse. NOTE: This is just an example, and not a real use-case for S2N, generally the public key would be parsed from 
the certificate associated with the device's private key.

This means that in order to make cryptographic devices usable with S2N, message signing must be deferred to PKCS #11. Currently signatures are created in S2N by calling the 
associated [libcrypto](https://www.openssl.org/docs/man1.1.1/man7/crypto.html) API, and there is no mechanism for modifying this operation's behavior.

There are a few approaches to this end, but my recommended approach is Option 1. 

## Option 1: Add functionality to the existing Async Private Key API
There already exists an interface exposed to the customer to allow for managing asynchronous private key operations. See the [USAGE_GUIDE](https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#asynchronous-private-key-operations-related-calls).
This option would still require some modification to the public API. 

This API can be extended to allow for offloading the signature operation to the application. 

The updated interface would something like this:

#### Signature function pointer signature
```c
typedef int (*s2n_sign_cb)( struct s2n_async_pkey_op *op, 
                 s2n_hash_algorithm hash_alg,  // Some signature algorithms need to know what hash algorithm was used to create the digest buffer.
                 const uint8_t * hash_buf,  // Byte array of digest S2N is requesting application to sign.
                 uint32_t hash_len); // size of hash_buf in bytes
```
#### Offload op
This op allows the application to inform S2N what function pointer to use for the signature callback. This function will later be called by S2N when it has a digest that it needs to sign.

```c
S2N_API
extern int s2n_async_pkey_op_offload(struct s2n_async_pkey_op *op, s2n_sign_cb sign_fn);
```

#### Copy signature op
This op allows the application to hand over the signature buffer to S2N. An alternative to this op is adding out parameters to the offload operation, so S2N can grab the signature buffer. This approach is okay, but adding a copy op is preferable because:
1. The management of the memory lifetime is easier to understand. The application can clean up safely after performing the copy op.
1. S2N can guard against use after free and similar memory mistakes that are common in C.
1. Follows the developer guidelines outlined in [quip](https://quip-amazon.com/jZw2AQUReED5/S2N-API-Guidelines).

```c
S2N_API
extern int s2n_async_pkey_op_copy(struct s2n_async_pkey_op *op,  uint8_t * sig, uint32_t siglen);
```

### Sample flow:
#### Callback example
```c
int async_pkey_apply_in_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    ... 
    s2n_async_pkey_op_type type; /* This is datatype is moved to the public API so the customer can make a decision on whether to offload the operation or not. */
    EXPECT_SUCCESS(s2n_async_get_op_type(op, &type));

    if(type == S2N_ASYNC_SIGN) /* The operation is asking for a signature, so provide S2N a pointer to the application's signature function. */
    {
        /* Perform the op */
        EXPECT_SUCCESS(s2n_async_pkey_op_offload(op, pkcs11_sign));
    }
    ...
```
#### Signature Example
```c
static int pkcs11_sign( struct s2n_async_pkey_op *op,
                 s2n_hash_algorithm hash_alg, 
                 const uint8_t * hash_buf, 
                 uint32_t hash_len )
{
    ...
    CK_ULONG siglen = 0;
    POSIX_GUARD(functionList->C_Sign(session,
                                       hash_buf,
                                       hash_len,
                                       NULL,
                                       &siglen));

    uint8_t * sig = malloc(siglen);
    POSIX_GUARD_PTR(sig);
    POSIX_GUARD(functionList->C_Sign(session,
                                       hash_buf,
                                       hash_len,
                                       sig,
                                       &siglen));

    EXPECT_SUCCESS(s2n_async_pkey_op_copy(op, sig, siglen));
    free(sig);
    ...
}
```

#### Application Setup Example
```c
    struct s2n_cert_chain_and_key *chain_and_key;
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE);
    chain_and_key = s2n_cert_chain_and_key_new());
    s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, NULL);

    struct s2n_config *config = s2n_config_new();
    s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key);
    s2n_config_add_dhparams(server_config, dhparams_pem);
    s2n_config_set_async_pkey_callback(server_config, async_pkey_apply_in_callback);
```

## Option 1: API Changes
Move hash algorithm enum from [crypto/s2n_hash.h](https://github.com/aws/s2n-tls/blob/b63d60b72396113014720ccda19eaffa559f6a52/crypto/s2n_hash.h#L28) to public API so S2N can inform
the application what was used to create the hash.

```c
typedef enum {
    S2N_HASH_NONE,
    S2N_HASH_MD5,
    S2N_HASH_SHA1,
    S2N_HASH_SHA224,
    S2N_HASH_SHA256,
    S2N_HASH_SHA384,
    S2N_HASH_SHA512,
    S2N_HASH_MD5_SHA1,
    /* Don't add any hash algorithms below S2N_HASH_SENTINEL */
    S2N_HASH_SENTINEL
} s2n_hash_algorithm;
```

Expose enum used to determine the async_pkey_op type. We only want to offload the signature, not the decrypt operation. Happy to take suggestions
on workarounds for this change.
```c
typedef enum { S2N_ASYNC_DECRYPT, S2N_ASYNC_SIGN } s2n_async_pkey_op_type;
S2N_API
extern int s2n_async_get_op_type(struct s2n_async_pkey_op *op, s2n_async_pkey_op_type * type);
```

New async operations.
```c
S2N_API
extern int s2n_async_pkey_op_offload(struct s2n_async_pkey_op *op, s2n_sign_cb sign_fn);
S2N_API
extern int s2n_async_pkey_op_copy(struct s2n_async_pkey_op *op,  uint8_t * sig, uint32_t siglen);
```

## Option 2: Add API to swap crypto abstraction signature function
There exists an s2n_pkey wrapper that could be a candidate for injecting a different signature function 
[here](https://github.com/aws/s2n-tls/blob/516a99ec134d0700f8de2ffc8072f1f949c5c3a3/crypto/s2n_pkey.c#L83). We can modify
the function pointer for sign and size to PKCS #11 specific functions, instead of wrappers for OpenSSL.

This allows for injecting a different signature implementation without changing much of the rest of S2N. 

Alternatively we can extend, the struct s2n_pkey with additional function pointers, and a user context pointer. Then these could be set with a 
config API for the user to toggle to the alternative function pointers.

Overall this option is much more intrusive than option 1, and does not respect the design boundaries of the various S2N components as much as option 1. 

#### Modified struct s2n_pkey
```c
struct s2n_pkey {
    /* Legacy OpenSSL APIs operate on specific keys, but the more recent
     * APIs all operate on EVP_PKEY. Let's store both for backwards compatibility. */
    union {
        struct s2n_rsa_key rsa_key;
        struct s2n_ecdsa_key ecdsa_key;
    } key;
    EVP_PKEY *pkey;

    S2N_RESULT (*size)(const struct s2n_pkey *key, uint32_t *size_out);
    int (*sign)(const struct s2n_pkey *priv_key, s2n_signature_algorithm sig_alg,
            struct s2n_hash_state *digest, struct s2n_blob *signature);
    int (*verify)(const struct s2n_pkey *pub_key, s2n_signature_algorithm sig_alg,
            struct s2n_hash_state *digest, struct s2n_blob *signature);
    int (*encrypt)(const struct s2n_pkey *key, struct s2n_blob *in, struct s2n_blob *out);
    int (*decrypt)(const struct s2n_pkey *key, struct s2n_blob *in, struct s2n_blob *out);
    int (*match)(const struct s2n_pkey *pub_key, const struct s2n_pkey *priv_key); 
    int (*free)(struct s2n_pkey *key);
    int (*check_key)(const struct s2n_pkey *key);
    /* Extended: */
    int (*alternate_sign)(void * ctx, s2n_hash_algorithm digest, 
                 const uint8_t * hash_buf, 
                 uint32_t hash_len,
                 uint8_t ** sig, 
                 uint32_t * sig_len,
                );
    int (*alternate_size)(void * ctx, uint32_t * size_out);
    void * ctx;
};
```

#### Altnerative Sign prototype
The benefit of using an alternate protype is that it doesn't expose internal types to the application. The negative 
is that the crypto abstraction layer is going to require more logic to manage switching between the two signature approaches.

This typedef would need to be added to api/s2n.h
```c
typedef int (*alternate_sign)(void * ctx, s2n_hash_algorithm digest, 
             const uint8_t * hash_buf, 
             uint32_t hash_len,
             uint8_t ** sig, 
             uint32_t * sig_len);
```

#### Alternative Size prototype
```c
typedef int (*alternate_size)(void * ctx, uint32_t * size_out);
```

Pros:
    * May require the smallest amount of external changes.
    * Asynchronous code should still work, as it sits on top of this abstraction.
Cons:
    * Questionable where this fits in with the overall design.

## Option 3: Direct PKCS #11 integration in S2N

We could directly add the logic to S2N for interfacing with PKCS #11. This approach seems to have no major upside that I can think of. The customer will still need to provide
the necessary data for S2N to configure the session with the Cryptoki implementation leading to duplicate effort, as we aren't solving their problem, just shifting the abstractions.

The other major negative is this would require major refactoring in S2N to make things work. This alone was enough to not really explore the option further.

Pros:
    * Signature is handled entirely by S2N.
    * Potential for other integrations like C_Encrypt or C_Digest type operations through the cryptographic device (Performance gains?). 
Cons:
    * Lots of effort for little to no upside.

# Signature callstacks
To help locate where S2N needs to generate signatures, here are example call stacks lifted from existing test cases.

### Mutual auth key signature 
#### Server
```
#0  s2n_pkey_sign (pkey=0xa7f000, sig_alg=S2N_SIGNATURE_RSA, digest=0xaaa8f8, signature=0x7fffffffac58) at /home/lundinc/opensource/s2n-tls/crypto/s2n_pkey.c:81
#1  0x00007ffff7870485 in s2n_async_pkey_sign_sync (conn=0xaa9000, sig_alg=S2N_SIGNATURE_RSA, digest=0xaaa8f8, on_complete=0x7ffff78af050 <s2n_server_key_send_write_signature>) at /home/lundinc/opensource/s2n-tls/tls/s2n_async_pkey.c:269
#2  0x00007ffff786fde3 in s2n_async_pkey_sign (conn=0xaa9000, sig_alg=S2N_SIGNATURE_RSA, digest=0xaaa8f8, on_complete=0x7ffff78af050 <s2n_server_key_send_write_signature>) at /home/lundinc/opensource/s2n-tls/tls/s2n_async_pkey.c:211
#3  0x00007ffff78af022 in s2n_server_key_send (conn=0xaa9000) at /home/lundinc/opensource/s2n-tls/tls/s2n_server_key_exchange.c:259
#4  0x00007ffff788be2b in s2n_handshake_write_io (conn=0xaa9000) at /home/lundinc/opensource/s2n-tls/tls/s2n_handshake_io.c:872
#5  0x00007ffff788b5a5 in s2n_negotiate (conn=0xaa9000, blocked=0x7fffffffaee0) at /home/lundinc/opensource/s2n-tls/tls/s2n_handshake_io.c:1290
#6  0x00000000004134c7 in s2n_negotiate_test_server_and_client (server_conn=0xaa9000, client_conn=0xab5000) at /home/lundinc/opensource/s2n-tls/tests/testlib/s2n_test_server_client.c:50
#7  0x0000000000406e6a in main (argc=1, argv=0x7fffffffde68) at /home/lundinc/opensource/s2n-tls/tests/unit/s2n_mutual_auth_test.c:119
```
#### Client - Only case that needs modification to use Async API
```
#0  s2n_pkey_sign (pkey=0xa7f000, sig_alg=S2N_SIGNATURE_RSA, digest=0xab8848, signature=0x7fffffffac70) at /home/lundinc/opensource/s2n-tls/crypto/s2n_pkey.c:81
#1  0x00007ffff7874791 in s2n_client_cert_verify_send (conn=0xab5000) at /home/lundinc/opensource/s2n-tls/tls/s2n_client_cert_verify.c:83
#2  0x00007ffff788be2b in s2n_handshake_write_io (conn=0xab5000) at /home/lundinc/opensource/s2n-tls/tls/s2n_handshake_io.c:872
#3  0x00007ffff788b5a5 in s2n_negotiate (conn=0xab5000, blocked=0x7fffffffaee0) at /home/lundinc/opensource/s2n-tls/tls/s2n_handshake_io.c:1290
#4  0x0000000000413470 in s2n_negotiate_test_server_and_client (server_conn=0xaa9000, client_conn=0xab5000) at /home/lundinc/opensource/s2n-tls/tests/testlib/s2n_test_server_client.c:47
#5  0x0000000000406e6a in main (argc=1, argv=0x7fffffffde68) at /home/lundinc/opensource/s2n-tls/tests/unit/s2n_mutual_auth_test.c:119
```

### Async private key signature
```
#0  s2n_pkey_sign (pkey=0x970000, sig_alg=S2N_SIGNATURE_RSA, digest=0xb47020, signature=0xb47118) at /home/lundinc/opensource/s2n-tls/crypto/s2n_pkey.c:81                                                                                                                  
#1  0x00007ffff7870b47 in s2n_async_pkey_sign_perform (op=0xb47000, pkey=0x970000) at /home/lundinc/opensource/s2n-tls/tls/s2n_async_pkey.c:422
#2  0x00007ffff786f783 in s2n_async_pkey_op_perform (op=0xb47000, key=0x970000) at /home/lundinc/opensource/s2n-tls/tls/s2n_async_pkey.c:290
#3  0x0000000000402b51 in async_pkey_apply_in_callback (conn=0xb4c000, op=0xb47000) at /home/lundinc/opensource/s2n-tls/tests/unit/s2n_async_pkey_test.c:128
#4  0x00007ffff786f1aa in s2n_async_pkey_sign_async (conn=0xb4c000, sig_alg=S2N_SIGNATURE_RSA, digest=0xb4d8f8, on_complete=0x7ffff78ae890 <s2n_server_key_send_write_signature>) at /home/lundinc/opensource/s2n-tls/tls/s2n_async_pkey.c:250
#5  0x00007ffff786ee01 in s2n_async_pkey_sign (conn=0xb4c000, sig_alg=S2N_SIGNATURE_RSA, digest=0xb4d8f8, on_complete=0x7ffff78ae890 <s2n_server_key_send_write_signature>) at /home/lundinc/opensource/s2n-tls/tls/s2n_async_pkey.c:213
#6  0x00007ffff78ae862 in s2n_server_key_send (conn=0xb4c000) at /home/lundinc/opensource/s2n-tls/tls/s2n_server_key_exchange.c:259
#7  0x00007ffff788b6eb in s2n_handshake_write_io (conn=0xb4c000) at /home/lundinc/opensource/s2n-tls/tls/s2n_handshake_io.c:872
#8  0x00007ffff788ae65 in s2n_negotiate (conn=0xb4c000, blocked=0x7fffffffad34) at /home/lundinc/opensource/s2n-tls/tls/s2n_handshake_io.c:1290
#9  0x000000000040f46c in try_handshake (server_conn=0xb4c000, client_conn=0xb9f000, handler=0x40f7a0 <async_handler_fail>) at /home/lundinc/opensource/s2n-tls/tests/unit/s2n_async_pkey_test.c:98
#10 0x0000000000406bf5 in main (argc=1, argv=0x7fffffffde78) at /home/lundinc/opensource/s2n-tls/tests/unit/s2n_async_pkey_test.c:210
```

# Changes to External API

# Multiple keys
In the case of the application storing multiple keys in the PKCS #11 module, and mapping them to multiple certificates in the S2N conn object, application will have enough data in the callback to determine which key to use. The signature of the async callback and the function to receive the selected certificate.
```c
typedef int (*s2n_async_pkey_fn)(struct s2n_connection *conn, struct s2n_async_pkey_op *op);
struct s2n_cert_chain_and_key s2n_connection_get_selected_cert(struct s2n_connection *conn);
```
Ussing the conn object, the a call to typedef int (*s2n_async_pkey_fn)(struct s2n_connection *conn, struct s2n_async_pkey_op *op);
`s2n_connection_get_selected_cert`
`s2n_cert_chain_and_key_get_key`

# RSA and EC
The logic may differ in the callback if the application has to use an EC vs an RSA key. The difference is fairly trivial, but it would be helpful to have a test for each case,
and example logic in the callback for correctly identifying what key should be used. (See ##Multiple_keys

# Tests/Examples
As part of this work I will provide an example integration with [SoftHSMv2](https://github.com/opendnssec/SoftHSMv2). This introduces the least risk, as I am familiar with it, 
and manpiluating the PKCS #11 objects with in it. I already have it working on my Cloud Desktop and linking to S2N.

As a quick follow up, an example integration / unit test with CloudHSM could be interesting to explore, but to keep the project on pace for the penetration test at the end 
of April, my preference is to first use SoftHSMv2 and add an example with CloudHSM as a nice to have.

The same goes for an example using Crypto authlib.

Note that these examples differ only in the setup steps, the exact same test code can and will be used with them.

# Appendix A: Implementation Details

# Appendix B: Glossary

