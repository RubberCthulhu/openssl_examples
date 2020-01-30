
#ifndef __OPENSSL_UTILS__
#define __OPENSSL_UTILS__

#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

char *read_file(const char *file, size_t *len);
int write_file(const char *file, const char *buf, size_t len);

X509 *X509_read_der(const char *buf, size_t size);
X509 *X509_read_pem(const char *buf, size_t size);
X509 *X509_read_file_der(const char *path);
X509 *X509_read_file_pem(const char *path);
X509 *X509_read_file(const char *path);
X509_CRL *X509_CRL_read_file_der(const char *path);
X509_CRL *X509_CRL_read_file_pem(const char *path);
X509_CRL *X509_CRL_read_file(const char *path);
EVP_PKEY *PrivateKey_read_file_der(const char *path);
EVP_PKEY *PrivateKey_read_file_pem(const char *path);
EVP_PKEY *PrivateKey_read_file(const char *path);
EVP_PKEY *PUBKEY_read_file_der(const char *path);
EVP_PKEY *PUBKEY_read_file_pem(const char *path);
EVP_PKEY *PUBKEY_read_file(const char *path);

#endif /* __OPENSSL_UTILS__ */
