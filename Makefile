SRC = $(wildcard *.c)
TARGET_MODULES = $(filter-out openssl_utils,$(SRC:.c=))
TARGETS = $(TARGET_MODULES:openssl_%=%)
LDFLAGS = -lssl -lcrypto

.PHONY: all
all: $(TARGETS)

sign: openssl_sign.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

verify: openssl_verify.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

cert_verify: openssl_cert_verify.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

verify_chain: openssl_verify_chain.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

verify_chain2: openssl_verify_chain2.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

store_verify_chain: openssl_store_verify_chain.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

check_issued: openssl_check_issued.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

aes128cbc_encode: openssl_aes128cbc_encode.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

aes128cbc_decode: openssl_aes128cbc_decode.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

cmac: openssl_cmac.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

parse_cert: openssl_parse_cert.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

eckey_by_object_curve: openssl_eckey_by_object_curve.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

eckey_by_object_curve2: openssl_eckey_by_object_curve2.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

shared_secret: openssl_shared_secret.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

priv2pub: openssl_priv2pub.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

subject_altname: openssl_subject_altname.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

x962: openssl_x962.c openssl_utils.c
	gcc -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	test -n "$(TARGETS)" && rm -Rf $(TARGETS)

