# List tokens
`p11tool --login --provider=/usr/local/lib/softhsm/libsofthsm2.so --set-pin=1111 --list-all`

# Use PKCS #11 for OpenSSL engine
```
openssl_conf = openssl_init

[openssl_init]
engines=engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib64/openssl/engines/pkcs11.so
MODULE_PATH = /usr/local/lib/softhsm/libsofthsm2.so
init = 0
```

# Create a token
`softhsm2-util --init-token --free --label mytoken2 --pin 0000 --so-pin 0000`

# Import an RSA key
`softhsm2-util --pin 0000 --import ./pkcs-test.p8 --token mytoken2 --id a000 --label rsa-privkey`

# Convert PKCS1 RSA key to PKCS8
`openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rsa_2048_pkcs1_key.pem -out pkcs-test.p8`
