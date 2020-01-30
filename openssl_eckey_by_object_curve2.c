
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl_utils.h"

static int get_ec_curve_name(const char *file);

int main(int argc, char **argv)
{
    EVP_PKEY *key = NULL, *params = NULL;
    EVP_PKEY_CTX *pctx = NULL, *kctx = NULL;
    FILE *f = NULL;
    int nid;

    if( argc != 3 ) {
	fprintf(stderr, "Usage: %s <in-private-key-or-public-key-or-cert> <out-private-key>\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    if( (nid = get_ec_curve_name(argv[1])) <= 0 ) {
        if( nid == -1 )
            fprintf(stderr, "Error: Unable to read <in-private-key-or-public-key-or-cert> from file %s\n", argv[1]);
        else if( nid == -2 )
            fprintf(stderr, "Error: Unsupported public key algorithm\n");
        else if( nid == 0 )
            fprintf(stderr, "Error: Unsupported curve\n");
        else
            fprintf(stderr, "Error: Unknown error\n");

        exit(EXIT_FAILURE);
    }
    
    if( !(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) ) {
	fprintf(stderr, "Error: EVP_PKEY_CTX_new_id(EVP_PKEY_EC): %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_PKEY_paramgen_init(pctx) != 1 ) {
	fprintf(stderr, "Error: EVP_PKEY_paramgen_init(): %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) != 1 ) {
	fprintf(stderr, "Error: EVP_PKEY_CTX_set_ec_paramgen_curve_nid(): %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_PKEY_paramgen(pctx, &params) != 1 ) {
	fprintf(stderr, "Error: EVP_PKEY_paramgen(): %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( !(kctx = EVP_PKEY_CTX_new(params, NULL)) ) {
	fprintf(stderr, "Error: EVP_PKEY_CTX_new(): %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_PKEY_keygen_init(kctx) != 1 ) {
	fprintf(stderr, "Error: EVP_PKEY_keygen_init(): %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( EVP_PKEY_keygen(kctx, &key) != 1 ) {
	fprintf(stderr, "Error: EVP_PKEY_keygen(): %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    if( !(f = fopen(argv[2], "w")) ) {
	fprintf(stderr, "Error: Unable to open file %s: %s\n", argv[2], strerror(errno));
	exit(EXIT_FAILURE);
    }
    
    if( PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) != 1 ) {
	fprintf(stderr, "Error: PEM_write_PrivateKey(<out-key>): %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    fclose(f);
    
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_free(key);
    
    exit(EXIT_SUCCESS);
}

static int get_ec_curve_name(const char *file)
{
    X509 *x509 = NULL;
    EVP_PKEY *key = NULL;
    int nid;

    if( key = PrivateKey_read_file(file) ) {

    }
    else if( key = PUBKEY_read_file(file) ) {

    }
    else if( x509 = X509_read_file(file) ) {
        key = X509_get_pubkey(x509);
    }
    else {
        return -1;
    }

    if( EVP_PKEY_base_id(key) != EVP_PKEY_EC )
        return -2;

    nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key)));

    EVP_PKEY_free(key);
    if( x509 )
        X509_free(x509);

    return nid;
}

