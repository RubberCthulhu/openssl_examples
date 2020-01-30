
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    char *key_buf, *msg_buf, *signed_buf;
    size_t key_buf_len, msg_buf_len, signed_buf_len;
    BIO *keybio;
    EVP_PKEY *key;
    EVP_MD_CTX *mdctx;
    
    if( argc != 4 ) {
	fprintf(stderr, "Usage: %s <private-key> <message> <signature>\n", argv[0]);
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
    
    keybio = BIO_new_mem_buf(key_buf, key_buf_len);
    if( !keybio ) {
	fprintf(stderr, "Error: Cant create key BIO\n");
	exit(EXIT_FAILURE);
    }
    
    key = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    if( !key ) {
	fprintf(stderr, "Error: Cant read private key from BIO\n");
	exit(EXIT_FAILURE);
    }
    
    BIO_free(keybio);
    free(key_buf);
    
    mdctx = EVP_MD_CTX_create();
    if( EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key) <= 0 ) {
	fprintf(stderr, "Error: EVP_DigestSignInit\n");
	exit(EXIT_FAILURE);
    }

    if( EVP_DigestSignUpdate(mdctx, msg_buf, msg_buf_len) <= 0 ) {
	fprintf(stderr, "Error: EVP_DigestSignUpdate\n");
	exit(EXIT_FAILURE);
    }

    if( EVP_DigestSignFinal(mdctx, NULL, &signed_buf_len) <= 0 ) {
	fprintf(stderr, "Error: EVP_DigestSignFinal\n");
	exit(EXIT_FAILURE);
    }

    signed_buf = (char *)malloc(signed_buf_len);
    if( EVP_DigestSignFinal(mdctx, signed_buf, &signed_buf_len) <= 0 ) {
	fprintf(stderr, "Error: EVP_DigestSignFinal\n");
	exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(key);
    free(msg_buf);

    if( write_file(argv[3], signed_buf, signed_buf_len) < 0 ) {
	fprintf(stderr, "Error: Cant write file %s: %s\n", argv[3], strerror(errno));
	exit(EXIT_FAILURE);
    }

    free(signed_buf);

    exit(EXIT_SUCCESS);
}
