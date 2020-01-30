
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    EVP_PKEY *private_key = NULL, *public_key = NULL;
    BIO *bio = NULL;
    FILE *f;
    
    if( argc != 3 ) {
	fprintf(stderr, "Usage: %s <in-private-key> <out-public-key>\n", argv[0]);
	exit(EXIT_FAILURE);
    }
    
    if( !(private_key = PrivateKey_read_file(argv[1])) ) {
	fprintf(stderr, "Error: Unable to read private key from file: PrivateKey_read_file() failed\n");
	exit(EXIT_FAILURE);
    }
    
    bio = BIO_new(BIO_s_mem());
    if( PEM_write_bio_PUBKEY(bio, private_key) != 1 ) {
	fprintf(stderr, "Error: PEM_write_bio_PUBKEY() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( !(public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)) ) {
	fprintf(stderr, "Error: PEM_read_bio_PUBKEY() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( !(f = fopen(argv[2], "w")) ) {
	fprintf(stderr, "Error: Unable top open file for writing: %s: %s\n", argv[2], strerror(errno));
	exit(EXIT_FAILURE);
    }
    
    if( PEM_write_PUBKEY(f, public_key) != 1 ) {
	fprintf(stderr, "Error: PEM_write_PUBKEY() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    fclose(f);
    BIO_free(bio);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    
    exit(EXIT_SUCCESS);
}

