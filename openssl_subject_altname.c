
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    X509 *cert;
    X509_EXTENSION *ext;
    BIO *bio;
    char *buf, *bptr;
    int loc;
    long len;
    
    if( argc != 2 ) {
	fprintf(stderr, "Usage: %s <cert>\n", argv[0]);
	exit(EXIT_FAILURE);
    }
    
    if( !(cert = X509_read_file(argv[1])) ) {
	fprintf(stderr, "Error: X509_read_file() failed\n");
	exit(EXIT_FAILURE);
    }
    
    if( (loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1)) < 0 ) {
	fprintf(stderr, "Error: subject alt name: not found\n");
	exit(EXIT_FAILURE);
    }
    
    ext = X509_get_ext(cert, loc);
    bio = BIO_new(BIO_s_mem());
    X509V3_EXT_print(bio, ext, 0, 0);
    BIO_flush(bio);
    len = BIO_get_mem_data(bio, &bptr);
    buf = (char *)malloc((len + 1) * sizeof(char));
    memcpy(buf, bptr, len);
    buf[len] = 0;

    fprintf(stdout, "%s\n", buf);
    
    BIO_free(bio);
    free(buf);
    X509_free(cert);
    
    exit(EXIT_SUCCESS);
}
