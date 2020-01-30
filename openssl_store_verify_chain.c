
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include "openssl_utils.h"

static int X509_STORE_load_from_dir(X509_STORE *store, const char *path);
static int verify_cb(int ok, X509_STORE_CTX *ctx);

int main(int argc, char **argv)
{
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *param = NULL;
    unsigned long flags = 0;
    X509 *leaf = NULL, *middle = NULL;
    X509_STORE_CTX *ctx = NULL;
    STACK_OF(X509) *untrusted = NULL;
    int status = 0;
    
    if( argc < 3 ) {
	fprintf(stderr, "Usage: %s <trusted-location> <leaf-cert> [<middle-cert>]\n", argv[0]);
	exit(EXIT_FAILURE);
    }
    
    store = X509_STORE_new();
    param = X509_STORE_get0_param(store);
    flags = X509_VERIFY_PARAM_get_flags(param);
    X509_VERIFY_PARAM_set_flags(param, flags | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_CRL_CHECK );
    X509_STORE_set_verify_cb(store, &verify_cb);
    /*if( X509_STORE_load_locations(store, NULL, argv[1]) != 1 ) {
	fprintf(stderr, "Error: X509_STORE_load_locations: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }*/
    if( X509_STORE_load_from_dir(store, argv[1]) < 0 ) {
	fprintf(stderr, "Error: X509_STORE_load_from_dir: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    
    leaf = X509_read_file(argv[2]);
    if( !leaf ) {
	fprintf(stderr, "Error: leaf: X509_read_file\n");
	exit(EXIT_FAILURE);
    }
    
    if( argc > 3 ) {
	middle = X509_read_file(argv[3]);
	if( !middle ) {
	    fprintf(stderr, "Error: middle: X509_read_file\n");
	    exit(EXIT_FAILURE);
	}
	
	untrusted = sk_X509_new_null();
	sk_X509_push(untrusted, middle);
    }
    
    ctx = X509_STORE_CTX_new();
    if( X509_STORE_CTX_init(ctx, store, leaf, untrusted) < 1 ) {
	fprintf(stderr, "Error: X509_STORE_CTX_init: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    status = X509_verify_cert(ctx);
    if( status == 1 ) {
	fprintf(stdout, "success\n");
    }
    else if( status == 0 ) {
	fprintf(stdout, "failure: invalid chain: %d: %s\n",
	    X509_STORE_CTX_get_error(ctx), X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }
    else {
	fprintf(stderr, "failure: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
	exit(EXIT_FAILURE);
    }
    
    X509_STORE_CTX_free(ctx);
    if( untrusted )
	sk_X509_free(untrusted);
    if( middle )
	X509_free(middle);
    X509_free(leaf);
    X509_STORE_free(store);
    
    exit(EXIT_SUCCESS);
}

static int X509_STORE_load_from_dir(X509_STORE *store, const char *path)
{
    DIR *dir;
    struct dirent *ent;
    struct stat pathstat;
    char *entpath;
    X509 *cert;
    X509_CRL *crl;
    int n = 0;
    
    if( !(dir = opendir(path)) )
	return -1;
    
    while( (ent = readdir(dir)) != NULL ) {
	entpath = (char *)malloc(strlen(path) + strlen(ent->d_name) + 2);
	sprintf(entpath, "%s/%s", path, ent->d_name);
	stat(entpath, &pathstat);
	if( S_ISREG(pathstat.st_mode) || S_ISLNK(pathstat.st_mode) ) {
	    if( cert = X509_read_file(entpath) ) {
		X509_STORE_add_cert(store, cert);
		X509_free(cert);
		n++;
	    }
	    else if( crl = X509_CRL_read_file(entpath) ) {
		X509_STORE_add_crl(store, crl);
		X509_CRL_free(crl);
		n++;
	    }
	}
	
	free(entpath);
    }

    closedir(dir);

    return n;
}

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
    int err, depth;
    
    if( !ok ) {
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);
	// Check crl only if we have it.
	if( err == X509_V_ERR_UNABLE_TO_GET_CRL ) {
	    return 1;
	}
	// Allowed only for leaf certificate.
	else if( err == X509_V_ERR_PERMITTED_VIOLATION && depth == 0 )
	    return 1;
    }

    return ok;
}
