
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include "openssl_utils.h"

#define FILENAME_STDIN1 "<-"
#define FILENAME_STDIN2 "-"
#define FILENAME_STDOUT ">-"
#define READ_BLOCK_SIZE 1024

static const char *get_filename_ext(const char *filename);

char *read_file(const char *file, size_t *len)
{
    FILE *f;
    char *buf;
    size_t n;
    
    if( strcmp(file, FILENAME_STDIN1) == 0 || strcmp(file, FILENAME_STDIN2) == 0 ) {
	buf = (char *)malloc(sizeof(char) * READ_BLOCK_SIZE);
	*len = 0;
	while( (n = fread(buf+(*len), sizeof(char), READ_BLOCK_SIZE, stdin)) == READ_BLOCK_SIZE ) {
	    *len += n;
	    buf = (char *)realloc(buf, sizeof(char) * ((*len) + READ_BLOCK_SIZE));
	}
	
	if( n > 0 )
	    *len += n;
    }
    else if( (f = fopen(file, "rb")) != NULL ) {
	fseek(f, 0, SEEK_END);
	*len = ftell(f);
	if( *len == 0 ) {
	    fclose(f);
	    return NULL;
	}
	
	fseek(f, 0, SEEK_SET);
	buf = (char *)malloc(*len);
	n = fread(buf, sizeof(char), *len, f);
	fclose(f);
	
	if( n != *len ) {
	    free(buf);
	    return NULL;
	}
    }
    else {
	buf = NULL;
    }

    return buf;
}

int write_file(const char *file, const char *buf, size_t len)
{
    FILE *f;
    int n, close = 1;
    
    if( strcmp(file, FILENAME_STDOUT) == 0 ) {
	f = stdout;
	close = 0;
    }
    else if( !(f = fopen(file, "wb")) ) {
	return -1;
    }
    
    n = fwrite(buf, sizeof(char), len, f);
    
    if( close )
	fclose(f);
    
    return n;
}

X509 *X509_read_der(const char *buf, size_t size)
{
    const unsigned char *buf_ptr = buf;
    return d2i_X509(NULL, &buf_ptr, size);
}

X509 *X509_read_pem(const char *buf, size_t size)
{
    BIO *bio;
    X509 *x509;

    bio = BIO_new_mem_buf(buf, size);
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return x509;
}

static const char *get_filename_ext(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    if( !dot || dot == filename ) return NULL;
    return dot + 1;
}

X509 *X509_read_file_der(const char *path)
{
    FILE *f = NULL;
    X509 *x509 = NULL;
    
    if( !(f = fopen(path, "r")) )
	return NULL;
    
    x509 = d2i_X509_fp(f, NULL);
    fclose(f);
    
    return x509;
}

X509 *X509_read_file_pem(const char *path)
{
    FILE *f = NULL;
    X509 *x509 = NULL;
    
    if( !(f = fopen(path, "r")) )
	return NULL;
    
    x509 = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    
    return x509;
}

X509 *X509_read_file(const char *path)
{
    const char *ext = NULL;
    X509 *x509;
    
    /* Default form - PEM. */
    ext = get_filename_ext(path);
    if( ext && (strcasecmp(ext, "der") == 0 || strcasecmp(ext, "crt") == 0 || strcasecmp(ext, "cer") == 0) )
	x509 = X509_read_file_der(path);
    else 
	x509 = X509_read_file_pem(path);

    return x509;
}

X509_CRL *X509_CRL_read_file_der(const char *path)
{
    FILE *f = NULL;
    X509_CRL *crl = NULL;
    
    if( !(f = fopen(path, "r")) )
	return NULL;
    
    crl = d2i_X509_CRL_fp(f, NULL);
    fclose(f);
    
    return crl;
}

X509_CRL *X509_CRL_read_file_pem(const char *path)
{
    FILE *f = NULL;
    X509_CRL *crl = NULL;
    
    if( !(f = fopen(path, "r")) )
	return NULL;
    
    crl = PEM_read_X509_CRL(f, NULL, NULL, NULL);
    fclose(f);
    
    return crl;
}

X509_CRL *X509_CRL_read_file(const char *path)
{
    const char *ext = NULL;
    X509_CRL *crl = NULL;
    
    /* Default form - PEM. */
    ext = get_filename_ext(path);
    if( ext && (strcasecmp(ext, "der") == 0) )
	crl = X509_CRL_read_file_der(path);
    else
	crl = X509_CRL_read_file_pem(path);

    return crl;
}

EVP_PKEY *PrivateKey_read_file_der(const char *path)
{
    FILE *f = NULL;
    EVP_PKEY *key = NULL;
    
    if( !(f = fopen(path, "r")) )
	return NULL;
    
    key = d2i_PrivateKey_fp(f, NULL);
    fclose(f);
    
    return key;
}

EVP_PKEY *PrivateKey_read_file_pem(const char *path)
{
    FILE *f = NULL;
    EVP_PKEY *key = NULL;
    
    if( !(f = fopen(path, "r")) )
	return NULL;
    
    key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    
    return key;
}

EVP_PKEY *PrivateKey_read_file(const char *path)
{
    const char *ext = NULL;
    EVP_PKEY *key = NULL;
    
    /* Default form - PEM. */
    ext = get_filename_ext(path);
    if( ext && (strcasecmp(ext, "der") == 0) )
	key = PrivateKey_read_file_der(path);
    else
	key = PrivateKey_read_file_pem(path);

    return key;
}

EVP_PKEY *PUBKEY_read_file_der(const char *path)
{
    FILE *f = NULL;
    EVP_PKEY *key = NULL;
    
    if( !(f = fopen(path, "r")) )
	return NULL;
    
    key = d2i_PUBKEY_fp(f, NULL);
    fclose(f);
    
    return key;
}

EVP_PKEY *PUBKEY_read_file_pem(const char *path)
{
    FILE *f = NULL;
    EVP_PKEY *key = NULL;
    
    if( !(f = fopen(path, "r")) )
	return NULL;
    
    key = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    
    return key;
}

EVP_PKEY *PUBKEY_read_file(const char *path)
{
    const char *ext = NULL;
    EVP_PKEY *key = NULL;
    
    /* Default form - PEM. */
    ext = get_filename_ext(path);
    if( ext && (strcasecmp(ext, "der") == 0) )
	key = PUBKEY_read_file_der(path);
    else
	key = PUBKEY_read_file_pem(path);

    return key;
}

