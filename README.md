# Certificate Validator

The following code validates the certificate provided by the server.
1. Connects to the server (eihter URL or IP, given with the command line)
2. Retrieves the ceritificate chain during the TLS handshake
3. Perform a detailed verification fo the ceritificate chain
4. Perform revocation checking using either CRL or OCSP


**Device:** Mac Air M1

## Preparation
### Install OpenSSL
OpenSSL pre-installed on MacOS

### Including OpenSSL libraries

You can include the libraries used by OpenSSL by running the following commands in your terminal:

```bash
export LIBRARY_PATH=$LIBRARY_PATH:/opt/homebrew/opt/openssl@3/lib/
export C_INCLUDE_PATH=$C_INCLUDE_PATH:/opt/homebrew/opt/openssl@3/include/
```

### Exporting Root CA

Mac stores its root CA in different ".keychain" files, which OpenSSL does not support. 
To export all root CA to ".pem" format (which is supported by OpenSSL), run the following command:

```bash
security export -t certs -f pemseq -k /System/Library/Keychains/SystemRootCertificates.keychain -o /tmp/all_certs.pem
```
Now, `/tmp/all_certs.pem` is the new location for root certs.

## Instructions
### Compile ***CertValidator.c***
```bash
clang sampleClient.c -o sampleClient -lssl -lcrypto
```

### Run ***CertValidator***
```
./sampleClient www.google.com
./sampleClient –v 147.46.10.129
./sampleClient –o expired-rsa-dv.ssl.com
```
