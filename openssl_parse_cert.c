
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include "openssl_utils.h"

int main(int argc, char **argv)
{
    X509 *cert = NULL;
    X509_NAME *subject;
    X509_NAME_ENTRY *entry;
    const ASN1_STRING *s;
    const ASN1_OCTET_STRING *os;
    int i, n;
    const unsigned char *p;
    
    if( argc < 2 ) {
	fprintf(stdout, "Usage: %s <cert>\n", argv[0]);
	exit(EXIT_FAILURE);
    }
    
    cert = X509_read_file(argv[1]);
    if( !cert ) {
	fprintf(stderr, "Error: X509_read_file: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(EXIT_FAILURE);
    }
    
    subject = X509_get_subject_name(cert);
    n = X509_NAME_entry_count(subject);
    fprintf(stdout, "Subject name entries:\n");
    for( i = 0 ; i < n ; i++ ) {
	X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, i);
	ASN1_STRING *s = X509_NAME_ENTRY_get_data(entry);
	fprintf(stdout, "%s\n", ASN1_STRING_get0_data(s));
    }

    fprintf(stdout, "-------------------------------\n");
    if( (i = X509_NAME_get_index_by_NID(subject, NID_serialNumber, -1)) != -1 ) {
	entry = X509_NAME_get_entry(subject, i);
	s = X509_NAME_ENTRY_get_data(entry);
	fprintf(stdout, "Subject: serialNumber: %s\n", ASN1_STRING_get0_data(s));
    }
    else {
	fprintf(stdout, "Subject: serialNumber: null\n");
    }
    
    if( (os = X509_get0_subject_key_id(cert)) != NULL ) {
	fprintf(stdout, "Subject key id:");
	n = ASN1_STRING_length(os);
	p = ASN1_STRING_get0_data(os);
	for( i = 0 ; i < n ; i++ ) {
	    fprintf(stdout, " %02X", (unsigned int)p[i]);
	}
	fprintf(stdout, "\n");
    }
    else {
	fprintf(stdout, "Subject key id: null\n");
    }
    
    X509_free(cert);
    
    exit(EXIT_FAILURE);
}
