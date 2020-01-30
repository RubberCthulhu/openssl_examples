
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/err.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    unsigned char *text = NULL, cmac[16];
    size_t textlen = 0, cmaclen;
    unsigned char *key = NULL;
    CMAC_CTX *ctx = NULL;
    
    if( argc < 2 ) {
	fprintf(stderr, "Usage: %s <key-%d-bytes> [<in> [<out>]]\n", argv[0], EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	exit(EXIT_FAILURE);
    }
    
    if( strlen(argv[1]) != EVP_CIPHER_key_length(EVP_aes_128_cbc()) ) {
	fprintf(stderr, "Error: key has to be %d bytes long\n", EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	exit(EXIT_FAILURE);
    }
    
    if( !(text = read_file(argc > 2 ? argv[2] : "-", &textlen)) ) {
	fprintf(stderr, "Error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    
    key = argv[1];
    
    ctx = CMAC_CTX_new();
    // Check if it's ok.
    CMAC_CTX_cleanup(ctx);
    
    if( CMAC_Init(ctx, key, strlen(key), EVP_aes_128_cbc(), NULL) != 1 ) {
	fprintf(stderr, "Error: CMAC_Init: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( CMAC_Update(ctx, text, textlen) != 1 ) {
	fprintf(stderr, "Error: CMAC_Update: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( CMAC_Final(ctx, cmac, &cmaclen) != 1 ) {
	fprintf(stderr, "Error: CMAC_Final: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    CMAC_CTX_free(ctx);
    
    write_file(argc > 3 ? argv[3] : ">-", cmac, cmaclen);
    
    exit(EXIT_SUCCESS);
}
