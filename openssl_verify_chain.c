
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
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    X509 *leaf = NULL, *middle = NULL, *root = NULL;
    STACK_OF(X509) *trusted = NULL, *untrusted = NULL;
    X509_CRL *crl_root = NULL, *crl_middle = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_VERIFY_PARAM *param = NULL;
    unsigned long flags = 0;
    int status = 0;
    
    if( argc < 4 ) {
	fprintf(stderr, "Usage: %s <root-cert> <middle-cert> <leaf-cert> [<root-crl> [<middle-crl>]]\n", argv[0]);
	exit(EXIT_FAILURE);
    }
    
    root = X509_read_file(argv[1]);
    if( !root ) {
	fprintf(stderr, "Error: root: X509_read_file\n");
	exit(EXIT_FAILURE);
    }
    
    middle = X509_read_file(argv[2]);
    if( !middle ) {
	fprintf(stderr, "Error: middle: X509_read_file\n");
	exit(EXIT_FAILURE);
    }
    
    leaf = X509_read_file(argv[3]);
    if( !leaf ) {
	fprintf(stderr, "Error: leaf: X509_read_file\n");
	exit(EXIT_FAILURE);
    }
    
    if( argc > 4 ) {
	crl_root = X509_CRL_read_file(argv[4]);
	if( !crl_root ) {
	    fprintf(stderr, "Error: crl_root: X509_CRL_read_file\n");
	    exit(EXIT_FAILURE);
	}
    }
    
    if( argc > 5 ) {
	crl_middle = X509_CRL_read_file(argv[5]);
	if( !crl_middle ) {
	    fprintf(stderr, "Error: crl_middle: X509_CRL_read_file\n");
	    exit(EXIT_FAILURE);
	}
    }
    
    if( crl_root && !crl_middle ) {
	store = X509_STORE_new();
	ctx = X509_STORE_CTX_new();
	trusted = sk_X509_new_null();
	sk_X509_push(trusted, root);

	if( X509_STORE_CTX_init(ctx, store, middle, NULL) < 1 ) {
	    fprintf(stderr, "Error: X509_STORE_CTX_init\n");
	    exit(EXIT_FAILURE);
	}
	
	X509_STORE_CTX_set0_trusted_stack(ctx, trusted);
	
	crls = sk_X509_CRL_new_null();
	sk_X509_CRL_push(crls, crl_root);
	X509_STORE_CTX_set0_crls(ctx, crls);
	param = X509_STORE_CTX_get0_param(ctx);
	flags = X509_VERIFY_PARAM_get_flags(param);
	X509_VERIFY_PARAM_set_flags(param, flags | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_CRL_CHECK);
	
	status = X509_verify_cert(ctx);
	if( status == 0 ) {
	    fprintf(stdout, "failure: invalid chain: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
	    exit(EXIT_SUCCESS);
	}
	else if( status != 1 ) {
	    fprintf(stderr, "failure: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
	    exit(EXIT_FAILURE);
	}
	
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	sk_X509_free(trusted);
	sk_X509_CRL_free(crls);
    }
    
    store = X509_STORE_new();
    ctx = X509_STORE_CTX_new();
    
    trusted = sk_X509_new_null();
    sk_X509_push(trusted, root);
    untrusted = sk_X509_new_null();
    sk_X509_push(untrusted, middle);
    
    if( X509_STORE_CTX_init(ctx, store, leaf, untrusted) < 1 ) {
	fprintf(stderr, "Error: X509_STORE_CTX_init\n");
	exit(EXIT_FAILURE);
    }
    
    X509_STORE_CTX_set0_trusted_stack(ctx, trusted);
    
    if( crl_root && crl_middle ) {
	crls = sk_X509_CRL_new_null();
	sk_X509_CRL_push(crls, crl_root);
	sk_X509_CRL_push(crls, crl_middle);
	X509_STORE_CTX_set0_crls(ctx, crls);
	param = X509_STORE_CTX_get0_param(ctx);
	flags = X509_VERIFY_PARAM_get_flags(param);
	//X509_VERIFY_PARAM_set_flags(param, flags | X509_V_FLAG_CRL_CHECK);
	X509_VERIFY_PARAM_set_flags(param, flags | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_CRL_CHECK);
	//X509_STORE_CTX_set0_param(ctx, param);
    }
    
    param = X509_STORE_CTX_get0_param(ctx);
    flags = X509_VERIFY_PARAM_get_flags(param);
    X509_VERIFY_PARAM_set_flags(param, flags | X509_V_FLAG_IGNORE_CRITICAL);
    //param = X509_STORE_CTX_get0_param(ctx);
    //printf("FLAGS: %lu\n", X509_VERIFY_PARAM_get_flags(param));
    
    status = X509_verify_cert(ctx);
    if( status == 1 ) {
	fprintf(stdout, "success\n");
    }
    else if( status == 0 ) {
	if( X509_STORE_CTX_get_error(ctx) == X509_V_ERR_PERMITTED_VIOLATION )
	    fprintf(stderr, "X509_V_ERR_PERMITTED_VIOLATION\n");
	fprintf(stdout, "failure: invalid chain: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }
    else {
	fprintf(stderr, "failure: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
	exit(EXIT_FAILURE);
    }
    
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(trusted);
    sk_X509_free(untrusted);
    if( crl_root ) {
	sk_X509_CRL_free(crls);
	X509_CRL_free(crl_root);
    }
    if( crl_middle )
	X509_CRL_free(crl_middle);
    X509_free(leaf);
    X509_free(middle);
    X509_free(root);
    
    exit(EXIT_SUCCESS);
}
