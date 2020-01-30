
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    X509 *issuer, *subject;
    
    if( argc != 3 ) {
	fprintf(stderr, "Usage: %s <issuer.der> <subject.der>\n", argv[0]);
	exit(EXIT_FAILURE);
    }
    
    issuer = X509_read_file(argv[1]);
    if( !issuer ) {
	fprintf(stderr, "Error: issuer: X509_read_file\n");
	exit(EXIT_FAILURE);
    }
    
    subject = X509_read_file(argv[2]);
    if( !subject ) {
	fprintf(stderr, "Error: subject: X509_read_file\n");
	exit(EXIT_FAILURE);
    }
    
    if( X509_check_issued(issuer, subject) == X509_V_OK ) {
	fprintf(stdout, "yes\n");
    }
    else {
	fprintf(stdout, "no\n");
    }
    
    X509_free(issuer);
    X509_free(subject);
    
    exit(EXIT_SUCCESS);
}
