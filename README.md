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
```bash
brew install openssl@1.1
```

### Including OpenSSL libraries

You can include the libraries used by OpenSSL by running the following commands in your terminal:

```bash
  export LDFLAGS="-L/opt/homebrew/opt/openssl@1.1/lib"
  export CPPFLAGS="-I/opt/homebrew/opt/openssl@1.1/include"
```

### Exporting Root CA

Mac stores its root CA in different ".keychain" files, which OpenSSL does not support. 
To export all root CA to ".pem" format (which is supported by OpenSSL), run the following command:

```bash
security export -t certs -f pemseq -k /System/Library/Keychains/SystemRootCertificates.keychain -o /tmp/all_certs.pem
```
Now, `/tmp/all_certs.pem` is the new location for root certs.

or

openssl library's root CA is located in `/opt/homebrew/etc/openssl@1.1/cert.pem`

both work the same

## Instructions
### Compile ***CertValidator.c***
```bash
clang++ CertValidator.cpp -o CertValidator -I/opt/homebrew/opt/openssl@1.1/include -L/opt/homebrew/opt/openssl@1.1/lib -lssl -lcrypto -lcurl
```

### Run ***CertValidator***
-v option for detailed cert info
-o for downloading certs in the chain
```
// examples
./CertValidator www.google.com
./CertValidator –v 147.46.10.129
./CertValidator –o expired-rsa-dv.ssl.com

// to test
// OCSP stapling, valid
./CertValidator naver.com

// for CRL/OCSP revoked cert test
./CertValidator revoked-rsa-dv.ssl.com 

```

## Reference
Openssl-ocsp : https://www.openssl.org/docs/man3.0/man1/openssl-ocsp.html

# Developer
Hyokwon Chung (hyochung@utexas.edu)