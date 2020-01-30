
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    unsigned char *shared_secret, *shared_info, out[32];
    size_t shared_secret_len, shared_info_len;
    
    if( argc != 4 ) {
	fprintf(stderr, "Usage: %s <in-shared-secret> <in-shared-info> <out-key>\n", argv[0]);
	exit(EXIT_FAILURE);
    }
    
    if( !(shared_secret = read_file(argv[1], &shared_secret_len)) ) {
	fprintf(stderr, "Error: Cant read file: %s\n", argv[1]);
	exit(EXIT_FAILURE);
    }
    
    if( !(shared_info = read_file(argv[2], &shared_info_len)) ) {
	fprintf(stderr, "Error: Cant read file: %s\n", argv[2]);
	exit(EXIT_FAILURE);
    }
    
    if( ECDH_KDF_X9_62(out, sizeof(out), shared_secret, shared_secret_len, shared_info, shared_info_len, EVP_sha256()) != 1 ) {
	fprintf(stderr, "Error: ECDH_KDF_X9_62() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( write_file(argv[3], out, sizeof(out)) < 0 ) {
	fprintf(stderr, "Error: Cant write file: %s\n", argv[3]);
	exit(EXIT_FAILURE);
    }
    
    exit(EXIT_SUCCESS);
}

