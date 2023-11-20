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

Mac stores its root CA in different ".keychain" files, which OpenSSL does not support. <br />
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
// Examples
./CertValidator www.google.com
./CertValidator –v 147.46.10.129
./CertValidator –o expired-rsa-dv.ssl.com

// Test
// OCSP stapling, valid
./CertValidator naver.com
// CRL/OCSP revoked 
./CertValidator revoked-rsa-dv.ssl.com 

```
### Sample Output
```
./CertValidator www.naver.com
OCSP response is stapled.

Certificate at depth: 0
Subject: /C=KR/ST=Gyeonggi-do/L=Seongnam-si/O=NAVER Corp./CN=www.naver.net
Issuer: /C=US/O=DigiCert Inc/CN=DigiCert TLS RSA SHA256 2020 CA1

CRL distribution points:
http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl

http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl

OCSP URI
http://ocsp.digicert.com

Certificate at depth: 1
Subject: /C=US/O=DigiCert Inc/CN=DigiCert TLS RSA SHA256 2020 CA1
Issuer: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA

Certificate at depth: 2
Subject: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA
Issuer: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA

Checking CRL...
CRL Distribution Point: http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl
Certificate is not revoked
CRL Distribution Point: http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl
Certificate is not revoked

Checking OCSP...
Certificate status: GOOD

```

## Reference
Openssl-ocsp : https://www.openssl.org/docs/man3.0/man1/openssl-ocsp.html

# Developer
Hyokwon Chung (hyochung@utexas.edu)