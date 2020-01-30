
all: sign verify cert_verify verify_chain verify_chain2 store_verify_chain check_issued aes128cbc_encode aes128cbc_decode cmac parse_cert eckey_by_object_curve eckey_by_object_curve2 shared_secret priv2pub subject_altname x962

sign: openssl_sign.c openssl_utils.c
	gcc openssl_sign.c openssl_utils.c -o sign -lssl -lcrypto

verify: openssl_verify.c openssl_utils.c
	gcc openssl_verify.c openssl_utils.c -o verify -lssl -lcrypto

cert_verify: openssl_cert_verify.c openssl_utils.c
	gcc openssl_cert_verify.c openssl_utils.c -o cert_verify -lssl -lcrypto

verify_chain: openssl_verify_chain.c openssl_utils.c
	gcc openssl_verify_chain.c openssl_utils.c -o verify_chain -lssl -lcrypto

verify_chain2: openssl_verify_chain2.c openssl_utils.c
	gcc openssl_verify_chain2.c openssl_utils.c -o verify_chain2 -lssl -lcrypto

store_verify_chain: openssl_store_verify_chain.c openssl_utils.c
	gcc openssl_store_verify_chain.c openssl_utils.c -o store_verify_chain -lssl -lcrypto

check_issued: openssl_check_issued.c openssl_utils.c
	gcc openssl_check_issued.c openssl_utils.c -o check_issued -lssl -lcrypto

aes128cbc_encode: openssl_aes128cbc_encode.c openssl_utils.c
	gcc openssl_aes128cbc_encode.c openssl_utils.c -o aes128cbc_encode -lssl -lcrypto

aes128cbc_decode: openssl_aes128cbc_decode.c openssl_utils.c
	gcc openssl_aes128cbc_decode.c openssl_utils.c -o aes128cbc_decode -lssl -lcrypto

cmac: openssl_cmac.c openssl_utils.c
	gcc openssl_cmac.c openssl_utils.c -o cmac -lssl -lcrypto

parse_cert: openssl_parse_cert.c openssl_utils.c
	gcc openssl_parse_cert.c openssl_utils.c -o parse_cert -lssl -lcrypto

eckey_by_object_curve: openssl_eckey_by_object_curve.c openssl_utils.c
	gcc openssl_eckey_by_object_curve.c openssl_utils.c -o eckey_by_object_curve -lssl -lcrypto

eckey_by_object_curve2: openssl_eckey_by_object_curve2.c openssl_utils.c
	gcc openssl_eckey_by_object_curve2.c openssl_utils.c -o eckey_by_object_curve2 -lssl -lcrypto

shared_secret: openssl_shared_secret.c openssl_utils.c
	gcc openssl_shared_secret.c openssl_utils.c -o shared_secret -lssl -lcrypto

priv2pub: openssl_priv2pub.c openssl_utils.c
	gcc openssl_priv2pub.c openssl_utils.c -o priv2pub -lssl -lcrypto

subject_altname: openssl_subject_altname.c openssl_utils.c
	gcc openssl_subject_altname.c openssl_utils.c -o subject_altname -lssl -lcrypto

x962: openssl_x962.c openssl_utils.c
	gcc openssl_x962.c openssl_utils.c -o x962 -lssl -lcrypto

clean:
	rm -Rf sign verify cert_verify verify_chain verify_chain2 check_issued aes128cbc_encode aes128cbc_decode cmac parse_cert eckey_by_object_curve eckey_by_object_curve2 shared_secret priv2pub subject_altname x962

