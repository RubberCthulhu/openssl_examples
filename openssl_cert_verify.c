
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    char *cert_buf, *msg_buf, *signed_buf;
    const unsigned char *cert_buf_ptr;
    size_t cert_buf_len, msg_buf_len, signed_buf_len;
    X509 *cert;
    EVP_PKEY *key;
    EVP_MD_CTX *mdctx;
    
    if( argc != 4 ) {
	fprintf(stderr, "Usage: %s <cert-der> <message> <signature>\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    if( !(cert_buf = read_file(argv[1], &cert_buf_len)) ) {
	fprintf(stderr, "Error: read file %s: %s\n", argv[1], strerror(errno));
	exit(EXIT_FAILURE);
    }
    
    if( !(msg_buf = read_file(argv[2], &msg_buf_len)) ) {
	fprintf(stderr, "Error: read file %s: %s\n", argv[2], strerror(errno));
	exit(EXIT_FAILURE);
    }
    
    if( !(signed_buf = read_file(argv[3], &signed_buf_len)) ) {
	fprintf(stderr, "Error: read file %s: %s\n", argv[3], strerror(errno));
	exit(EXIT_FAILURE);
    }
    
    cert_buf_ptr = cert_buf;
    cert = d2i_X509(NULL, &cert_buf_ptr, cert_buf_len);
    if( !cert ) {
	fprintf(stderr, "Error: d2i_X509\n");
	exit(EXIT_FAILURE);
    }
    
    free(cert_buf);
    
    key = X509_get_pubkey(cert);
    if( !key ) {
	fprintf(stderr, "Error: X509_get_pubkey\n");
	exit(EXIT_FAILURE);
    }
    
    mdctx = EVP_MD_CTX_create();
    if( EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key) <= 0 ) {
	fprintf(stderr, "Error: EVP_DigestVerifyInit\n");
	exit(EXIT_FAILURE);
    }

    if( EVP_DigestVerifyUpdate(mdctx, msg_buf, msg_buf_len) <= 0 ) {
	fprintf(stderr, "Error: EVP_DigestVerifyUpdate\n");
	exit(EXIT_FAILURE);
    }

    int status = EVP_DigestVerifyFinal(mdctx, signed_buf, signed_buf_len);
    if( status == 1 ) {
	fprintf(stdout, "success\n");
    }
    else if( status == 0 ) {
	fprintf(stdout, "failure: signature invalid\n");
    }
    else {
	char err[256];
	ERR_error_string_n(ERR_get_error(), err, 256);
	fprintf(stderr, "failure: error: %s\n", err);
	exit(EXIT_FAILURE);
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(key);
    X509_free(cert);
    free(msg_buf);
    free(signed_buf);
    
    exit(EXIT_SUCCESS);
}
