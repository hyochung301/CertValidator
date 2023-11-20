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
#include <curl/curl.h>
#include <vector>
#include <string>
#include <iostream>
using namespace std;


int get_ocsp_responder_uri(X509 *cert){
        STACK_OF(OPENSSL_STRING) *aia = X509_get1_ocsp(cert);
        if (aia) {
            string uri = new char[256];
            uri = sk_OPENSSL_STRING_value(aia, 0);
            cout << "OCSP URI" << endl << uri << endl << endl;
            sk_OPENSSL_STRING_free(aia);
            return 0;
        } else {
            cout << "No OCSP responder URI found." << endl;
            return -1;
        }
}

void download_crl(const char* url, const char* filename) {
    CURL *curl;
    FILE *fp;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        fp = fopen(filename, "wb");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res = curl_easy_perform(curl);
        /* Check for errors */ 
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        /* always cleanup */ 
        curl_easy_cleanup(curl);
        fclose(fp);
    }
}

std::vector<std::string> get_crl_distribution_point(X509 *cert) {
    int i, j;
    std::vector<std::string> crl_dist_points;

    // Get the CRL distribution points extension
    STACK_OF(DIST_POINT) * distpoints = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);

    if (distpoints) {
        std::cout << "CRL distribution points:" << std::endl;

        // Loop through the distribution points
        for (i = 0; i < sk_DIST_POINT_num(distpoints); i++) {
            DIST_POINT *distpoint = sk_DIST_POINT_value(distpoints, i);

            // The distribution point is a URI
            if (distpoint->distpoint && distpoint->distpoint->type == 0) {

                // Loop through the GENERAL_NAMEs
                for (j = 0; j < sk_GENERAL_NAME_num(distpoint->distpoint->name.fullname); j++) {
                    GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->distpoint->name.fullname, j);

                    if (gen->type == GEN_URI) {
                        ASN1_STRING *uri = gen->d.uniformResourceIdentifier;
                        // Convert the data to a C string
                        std::string crl_dist_point = std::string((char *)ASN1_STRING_get0_data(uri));                        
                        std::cout << crl_dist_point << std::endl << std::endl;

                        // Add the CRL distribution point to the vector
                        crl_dist_points.push_back(crl_dist_point);
                    }
                }
            } else {
                std::cout << "No distribution point found." << std::endl;
            }
        }

        // Free the distribution points
        sk_DIST_POINT_free(distpoints);
    } else {
        std::cout << "No CRL distribution points extension found.\n";
    }

    return crl_dist_points;
}

// Function to check if a certificate is revoked
bool revocation_check_driver_crl(X509 *cert, X509_CRL *crl) {
    // Driver that actually checks CRL revocation by parsing through crl
    // Called by crl_revocation()

    // Get the serial number of the certificate
    ASN1_INTEGER *cert_serial = X509_get_serialNumber(cert);

    // Get the list of revoked certificates
    STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);

    // Check each revoked certificate
    for (int i = 0; i < sk_X509_REVOKED_num(revoked); i++) {
        X509_REVOKED *rev = sk_X509_REVOKED_value(revoked, i);

        // Get the serial number of the revoked certificate
        const ASN1_INTEGER *rev_serial = X509_REVOKED_get0_serialNumber(rev);

        // Compare the serial numbers
        if (ASN1_INTEGER_cmp(cert_serial, rev_serial) == 0) {
            std::cout << "Certificate revoked"<< endl;

            // Get the revocation date
            const ASN1_TIME *rev_time = X509_REVOKED_get0_revocationDate(rev);

            // Convert the revocation date to a string
            BIO *bio = BIO_new(BIO_s_mem());
            ASN1_TIME_print(bio, rev_time);
            BUF_MEM *bptr;
            BIO_get_mem_ptr(bio, &bptr);

            // Print the revocation time
            std::string time_str(bptr->data, bptr->length);
            std::cout << "Revocation Time: " << time_str << endl;

            // Clean up
            BIO_free(bio);

            // The certificate is revoked
            return true;
        }
    }

    // The certificate is not revoked
    cout << "Certificate is not revoked" << endl;
    return false;
}

int crl_revocation(X509 *cert, vector<string> &crl_dist_points) {
    // Call this function to check if a certificate is revoked using CRL

    // Get the leaf certificate
    if (cert == NULL) {
        fprintf(stderr, "Error getting leaf certificate.\n");
        return -1;
    }
    // Create a new X509_STORE
    X509_STORE *store = X509_STORE_new();
    if (store == NULL) {
        fprintf(stderr, "Error creating X509_STORE.\n");
        return -1;
    }

    // Loop over the CRL distribution points
    for (const auto& crl_dist_point : crl_dist_points) {
        // Convert the string to a C string
        const char *crl_dist_point_c_str = crl_dist_point.c_str();

        // Download the CRL
        if (crl_dist_point_c_str) {
            download_crl(crl_dist_point_c_str, "crl.crl");
        } else {
            fprintf(stderr, "Error: CRL distribution point is NULL.\n");
            return -1;
        }
        
        printf("CRL Distribution Point: %s\n", crl_dist_point_c_str);

        // Load the CRL
        BIO *bio = BIO_new_file("crl.crl", "rb");
        if (!bio) {
            fprintf(stderr, "Error opening file.\n");
            return -1;
        }

        X509_CRL *crl = d2i_X509_CRL_bio(bio, NULL);
        if (!crl) {
            fprintf(stderr, "Error reading CRL.\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }

        if (revocation_check_driver_crl(cert, crl) == true) {
            return 1;
        }
    }

    return 0;
}

// Function to check if a certificate has expired
int check_expiration(X509 *cert) {
    // Get the notAfter field from the certificate
    ASN1_TIME* notAfter = X509_get_notAfter(cert);

    // Convert the notAfter field to a string
    BIO* bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, notAfter);
    char* notAfterStr = new char[128];
    memset(notAfterStr, 0, 128);
    BIO_read(bio, notAfterStr, 128 - 1);
    BIO_free(bio);

    // Check if the certificate has expired
    if (X509_cmp_current_time(notAfter) < 0) {
        printf("Certificate has expired on %s\n", notAfterStr);
        delete[] notAfterStr;
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

    if (!SSL_CTX_load_verify_locations(ctx, "/opt/homebrew/etc/openssl@1.1/cert.pem", NULL)) {
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
        printf("OCSP response is stapled.\n\n");
        
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
        printf("No OCSP stapling response received.\n\n");
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

    // Check if the certificate has been revoked
    //if (crl_revocation(sk_X509_value(cert_chain, 0)) != 0) {
    //    printf("Certificate has been revoked\n");
    //    return 0;
    //}
    vector<string> crl_dist_points; 
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
        // Get CRL distribution points and OCSP responder URI
        if (i == 0) {
            crl_dist_points = get_crl_distribution_point(cert);
            get_ocsp_responder_uri(cert);
        }
    }
    // Check if the certificate has been revoked
    // CRL
    cout << "Checking CRL..." << endl;
    X509 *leaf_cert = sk_X509_value(cert_chain, 0);
    if (crl_revocation(leaf_cert, crl_dist_points) == -1) {
        printf("Certificate is cannot be checked using CRL\n");
    }

    // OCSP
    cout << endl << "Checking OCSP..." << endl;
    cout << "Certificate status: Not implemented yet" << endl;

    // Clean up
    ERR_clear_error();
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
