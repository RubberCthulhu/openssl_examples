
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    unsigned char *text = NULL, *ciphertext = NULL;
    size_t ciphertext_len = 0;
    int text_len, text_maxlen, len;
    unsigned char *key = NULL, *iv = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    
    if( argc < 3 ) {
	fprintf(stderr, "Usage: %s <key-%d-bytes> <iv-%d-bytes> [<in> [<out>]]\n",
	    argv[0], EVP_CIPHER_key_length(EVP_aes_128_cbc()), EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	exit(EXIT_FAILURE);
    }
    
    if( strlen(argv[1]) != EVP_CIPHER_key_length(EVP_aes_128_cbc()) ) {
	fprintf(stderr, "Error: key has to be %d bytes long\n", EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	exit(EXIT_FAILURE);
    }
    
    if( strlen(argv[2]) != EVP_CIPHER_iv_length(EVP_aes_128_cbc()) ) {
	fprintf(stderr, "Error: iv has to be %d bytes long\n", EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	exit(EXIT_FAILURE);
    }

    if( !(ciphertext = read_file(argc > 3 ? argv[3] : "-", &ciphertext_len)) ) {
	fprintf(stderr, "Error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }

    key = argv[1];
    iv = argv[2];
    /* It isn't clear if ciphertext_len + EVP_CIPHER_block_size(EVP_aes_128_cbc()) is enough for both
       EVP_DecryptUpdate and EVP_DecryptFinal_ex or we need EVP_CIPHER_block_size(EVP_aes_128_cbc()) bytes more
       for EVP_DecryptFinal_ex. */
    text_maxlen = ciphertext_len + EVP_CIPHER_block_size(EVP_aes_128_cbc())*2;
    text = (unsigned char *)malloc(text_maxlen * sizeof(unsigned char));
    
    ctx = EVP_CIPHER_CTX_new();
    // Check if it is ok to reset context right after creation.
    if( EVP_CIPHER_CTX_reset(ctx) != 1 ) {
	fprintf(stderr, "Error: EVP_CIPHER_CTX_reset: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1 ) {
	fprintf(stderr, "Error: EVP_DecryptInit_ex: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_DecryptUpdate(ctx, text, &len, ciphertext, ciphertext_len) != 1 ) {
	fprintf(stderr, "Error: EVP_DecryptUpdate: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    text_len = len;
    // TODO Find out if we need to use either EVP_DecryptFinal_ex or EVP_DecryptFinal.
    if( EVP_DecryptFinal_ex(ctx, text + len, &len) != 1 ) {
	fprintf(stderr, "Error: EVP_DecryptFinal_ex: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    text_len += len;
    EVP_CIPHER_CTX_free(ctx);
    
    write_file(argc > 4 ? argv[4] : ">-", text, text_len);
    free(text);
    
    exit(EXIT_SUCCESS);
}
