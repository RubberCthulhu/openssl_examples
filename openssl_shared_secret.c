
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    EVP_PKEY *private_key = NULL, *public_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *shs = NULL;
    size_t shs_len = 0;
    int err;

    if( argc != 4 ) {
	fprintf(stderr, "Usage: %s <in-private-key> <in-public-key> <out-shared-secret>\n", argv[0]);
	exit(EXIT_FAILURE);
    }
    
    if( !(private_key = PrivateKey_read_file(argv[1])) ) {
	fprintf(stderr, "Error: Unable to read private key from file: PrivateKey_read_file() failed\n");
	exit(EXIT_FAILURE);
    }
    
    if( !(public_key = PUBKEY_read_file(argv[2])) ) {
	fprintf(stderr, "Error: Unable to read public key from file: PUBKEY_read_file() failed\n");
	exit(EXIT_FAILURE);
    }
    
    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if( (err = EVP_PKEY_derive_init(ctx)) != 1 ) {
	fprintf(stderr, "Error: EVP_PKEY_derive_init() failed: %s%s\n",
	    err == -2 ? "Operation isn't supported by the public key algorithm: " : "", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_PKEY_derive_set_peer(ctx, public_key) != 1 ) {
	fprintf(stderr, "Error: EVP_PKEY_derive_set_peer() failed: %s%s\n",
	    err == -2 ? "Operation isn't supported by the public key algorithm: " : "", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_PKEY_derive(ctx, NULL, &shs_len) != 1 ) {
	fprintf(stderr, "Error: EVP_PKEY_derive() failed: %s%s\n",
	    err == -2 ? "Operation isn't supported by the public key algorithm: " : "", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    shs = OPENSSL_malloc(shs_len);
    if( EVP_PKEY_derive(ctx, shs, &shs_len) != 1 ) {
	fprintf(stderr, "Error: EVP_PKEY_derive() failed: %s%s\n",
	    err == -2 ? "Operation isn't supported by the public key algorithm: " : "", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( write_file(argv[3], shs, shs_len) < 0 ) {
	fprintf(stderr, "Error: write_file(%s) failed: %s", argv[3], strerror(errno));
	exit(EXIT_FAILURE);
    }
    
    OPENSSL_free(shs);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    
    exit(EXIT_SUCCESS);
}

