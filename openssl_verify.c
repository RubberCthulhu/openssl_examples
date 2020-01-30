
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    char *key_buf, *msg_buf, *signed_buf;
    size_t key_buf_len, msg_buf_len, signed_buf_len;
    BIO *keybio;
    EVP_PKEY *key;
    EVP_MD_CTX *mdctx;
    
    if( argc != 4 ) {
	fprintf(stderr, "Usage: %s <public-key> <message> <signature>\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    if( !(key_buf = read_file(argv[1], &key_buf_len)) ) {
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
    
    keybio = BIO_new_mem_buf(key_buf, key_buf_len);
    if( !keybio ) {
	fprintf(stderr, "Error: Cant create key BIO\n");
	exit(EXIT_FAILURE);
    }
    
    key = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
    if( !key ) {
	fprintf(stderr, "Error: Cant read public key from BIO\n");
	exit(EXIT_FAILURE);
    }
    
    BIO_free(keybio);
    free(key_buf);
    
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
	fprintf(stderr, "failure: signature invalid\n");
    }
    else {
	char err[256];
	ERR_error_string_n(ERR_get_error(), err, 256);
	fprintf(stderr, "failure: error: %s\n", err);
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(key);
    free(msg_buf);
    free(signed_buf);
    
    if( status != 1 )
	exit(EXIT_FAILURE);

    exit(EXIT_SUCCESS);
}
