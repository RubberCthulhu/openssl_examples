
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
    size_t textlen = 0;
    int ciphertext_len, ciphertext_maxlen, len;
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

    if( !(text = read_file(argc > 3 ? argv[3] : "-", &textlen)) ) {
	fprintf(stderr, "Error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }

    key = argv[1];
    iv = argv[2];
    /* It isn't clear if textlen + EVP_CIPHER_block_size(EVP_aes_128_cbc()) - 1 is enough for both
       EVP_EncryptUpdate and EVP_EncryptFinal_ex or we need EVP_CIPHER_block_size(EVP_aes_128_cbc()) bytes more
       for EVP_EncryptFinal_ex. */
    ciphertext_maxlen = textlen + EVP_CIPHER_block_size(EVP_aes_128_cbc())*2 - 1;
    ciphertext = (unsigned char *)malloc(ciphertext_maxlen * sizeof(unsigned char));
    
    ctx = EVP_CIPHER_CTX_new();
    // Check if is is ok to reset cipher context.
    if( EVP_CIPHER_CTX_reset(ctx) != 1 ) {
	fprintf(stderr, "Error: EVP_CIPHER_CTX_reset: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1 ) {
	fprintf(stderr, "Error: EVP_EncryptInit_ex: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_EncryptUpdate(ctx, ciphertext, &len, text, textlen) != 1 ) {
	fprintf(stderr, "Error: EVP_EncryptUpdate: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    ciphertext_len = len;
    
    if( EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1 ) {
	fprintf(stderr, "Error: EVP_EncryptFinal_ex: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    
    write_file(argc > 4 ? argv[4] : ">-", ciphertext, ciphertext_len);
    free(ciphertext);
    
    exit(EXIT_SUCCESS);
}
