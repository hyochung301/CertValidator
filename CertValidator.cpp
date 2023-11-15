#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/bio.h>

#include <iostream>
using namespace std;


// Function to check if a certificate has expired
int check_expiration(X509 *cert) {
    // Get the notAfter field from the certificate
    ASN1_TIME* notAfter = X509_get_notAfter(cert);

    // Convert the notAfter field to a string
    BIO* bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, notAfter);
    char* notAfterStr = new char(128);
    memset(notAfterStr, 0, 128);
    BIO_read(bio, notAfterStr, 128 - 1);
    BIO_free(bio);

    // Check if the certificate has expired
    if (X509_cmp_current_time(notAfter) < 0) {
        printf("Certificate has expired on %s\n", notAfterStr);
        free(notAfterStr);
        return 0;
    }

    delete[] notAfterStr;
    return 1;
}

// Callback function for custom certificate verification
int verify_callback(int preverify, X509_STORE_CTX* x509_ctx) {
    // Retrieve the certificate from the context
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert == NULL) {
        printf("Error retrieving certificate\n");
        return 0;
    }

    // Check if the certificate has expired
    if (!check_expiration(cert)) {
        printf("Certificate has expired\n");
        return 0;
    }

    // If preverification failed, print the specific error
    if (!preverify) {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("Verification error: %s\n", X509_verify_cert_error_string(err));
    }

    return 1; // Even if it fails, return 1 to continue with the cert verification process
}


void print_certificate(X509 *cert) {
    if (cert) {
        printf("Certificate:\n");
        X509_print_fp(stdout, cert);
        printf("\n");
    }
}

void print_certificate_info(X509 *cert, int depth) {
    X509_NAME *subj = X509_get_subject_name(cert);
    X509_NAME *issuer = X509_get_issuer_name(cert);

    char subj_str[256];
    char issuer_str[256];

    // Convert the names to a readable string
    X509_NAME_oneline(subj, subj_str, sizeof(subj_str));
    X509_NAME_oneline(issuer, issuer_str, sizeof(issuer_str));

    // Print the certificate details at the given depth
    printf("Certificate at depth: %d\n", depth);
    printf("Subject: %s\n", subj_str);
    printf("Issuer: %s\n\n", issuer_str);
}

void save_certificate(X509 *cert, const char *filename) {
    if (cert) {
        FILE *fp = fopen(filename, "w");
        if (fp) {
            PEM_write_X509(fp, cert);
            fclose(fp);
            printf("Saved certificate to %s\n", filename);
        } else {
            fprintf(stderr, "Could not open %s for writing.\n", filename);
        }
    }
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    X509 *cert;
    STACK_OF(X509) *cert_chain;
    int option;
    int verbose = 0, output_files = 0;

    while ((option = getopt(argc, argv, "vo")) != -1) {
        switch (option) {
            case 'v': verbose = 1; break;
            case 'o': output_files = 1; break;
            default: fprintf(stderr, "Invalid option\n");
                     exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Usage: %s [-v|-o] <host>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *host = argv[optind];

    // Initialize OpenSSL
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "/opt/homebrew/etc/openssl@3/cert.pem", NULL)) {
        fprintf(stderr, "Error setting up trust store.\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // automatic chain verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);


    // Create a new BIO chain with an SSL BIO using the context
    bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set up the SSL
    BIO_get_ssl(bio, &ssl);
    if (ssl == NULL) {
        fprintf(stderr, "Error getting SSL.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set the SNI hostname
    SSL_set_tlsext_host_name(ssl, host);

    // Set up the connection to the remote host
    BIO_set_conn_hostname(bio, host);
    BIO_set_conn_port(bio, "443");

    // Enable OCSP stapling
    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);

    // Attempt to connect
    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to remote host.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Attempt to do the TLS/SSL handshake
    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "Error establishing SSL connection.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    long verification_result = SSL_get_verify_result(ssl);
    if (verification_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification error: %ld (%s)\n",
                verification_result, X509_verify_cert_error_string(verification_result));
    }

    // Check for stapled OCSP response
    const unsigned char *ocsp_resp;
    long ocsp_resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &ocsp_resp);
    OCSP_RESPONSE *response = NULL;

    if (ocsp_resp_len > 0) {
        printf("OCSP response is stapled.\n");
        
        // Decode the OCSP response
        const unsigned char *p = ocsp_resp; // temporary pointer
        response = d2i_OCSP_RESPONSE(NULL, &p, ocsp_resp_len);
        if (response) {
            if (verbose) {
                OCSP_RESPONSE_print(BIO_new_fp(stdout, BIO_NOCLOSE), response, 0);
            }
            
            if (output_files) {
                // Save the OCSP response to a file
                FILE *fp = fopen("ocsp.pem", "wb");
                if (fp != NULL) {
                    const int length = i2d_OCSP_RESPONSE(response, NULL);
                    if (length > 0) {
                        unsigned char *der = new unsigned char[length];;
                        unsigned char *p = der;
                        if (i2d_OCSP_RESPONSE(response, &p) > 0) {
                            fwrite(der, 1, length, fp);
                            printf("OCSP response saved to ocsp.pem\n");
                        } else {
                            fprintf(stderr, "Error converting OCSP response to DER format.\n");
                        }
                        delete[] der;
                    } else {
                        fprintf(stderr, "Error determining OCSP response length.\n");
                    }
                    fclose(fp);
                } else {
                    fprintf(stderr, "Unable to open ocsp.pem for writing.\n");
                }
            }
            OCSP_RESPONSE_free(response);
        } else {
            fprintf(stderr, "Failed to decode OCSP response.\n");
        }
    } else {
        printf("No OCSP stapling response received.\n");
    }

    // Retrieve the certificate chain
    cert_chain = SSL_get_peer_cert_chain(ssl);
    if (cert_chain == NULL) {
        fprintf(stderr, "Error getting certificate chain.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Print details for each certificate in the chain
    for (int i = 0; i < sk_X509_num(cert_chain); i++) {
        cert = sk_X509_value(cert_chain, i);
        if (verbose) {
            print_certificate(cert);
        } else {
        // For non-verbose, print simplified information
        print_certificate_info(cert, i);
        }
        if (output_files) {
            char filename[32];
            snprintf(filename, sizeof(filename), "depth%d.pem", i);
            save_certificate(cert, filename);
        }

        // Get CRL distribution points
        STACK_OF(DIST_POINT) *crldp = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);

    }

    // Obtain the issuing certificate.
    if (crldp) {
        for (int i = 0; i < sk_DIST_POINT_num(crldp); i++) {
            DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
            if (dp->distpoint && dp->distpoint->type == GEN_URI) {
                char *uri = (char *)ASN1_STRING_get0_data(dp->distpoint->name.fullname);
                printf("CRL distribution point URI: %s\n", uri);
            }
        }
        sk_DIST_POINT_free(crldp);
    } else {
        printf("No CRL distribution point found.\n");
    }

    // Download the CRL
    BIO *bio = BIO_new(BIO_s_file());
    if (BIO_read_filename(bio, uri) <= 0) {
        fprintf(stderr, "Error downloading CRL.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        exit(EXIT_FAILURE);
    }

    // Load the CRL
    X509_CRL *crl = d2i_X509_CRL_bio(bio, NULL);
    if (crl == NULL) {
        fprintf(stderr, "Error loading CRL.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        exit(EXIT_FAILURE);
    }

    // Get the certificate's serial number
    ASN1_INTEGER *cert_serial = X509_get_serialNumber(leaf_cert);

    // Look for the certificate serial number in the CRL
    STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);
    for (int i = 0; i < sk_X509_REVOKED_num(revoked); i++) {
        X509_REVOKED *rev = sk_X509_REVOKED_value(revoked, i);
        if (ASN1_INTEGER_cmp(cert_serial, X509_REVOKED_get0_serialNumber(rev)) == 0) {
            printf("Certificate is revoked.\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("Certificate is not revoked.\n");

    // Clean up
    X509_CRL_free(crl);
    ERR_clear_error();
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}
