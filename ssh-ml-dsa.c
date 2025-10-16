/*
 * Copyright (c) 2025 Thomas Lind Nielsen <tln@tlind.xyz>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include "openbsd-compat/openssl-compat.h"
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "log.h"

u_int
ssh_ml_dsa_size(
    const struct sshkey *key
) {
    // printf("ml-dsa: size function called\n");
    return SSH_ERR_INTERNAL_ERROR;
}	/* optional */

int 
ssh_ml_dsa_alloc(
    struct sshkey *key
) {
    if ((key->pkey = EVP_PKEY_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	return 0;
}		/* optional */

void
ssh_ml_dsa_cleanup(
    struct sshkey *key
) {
    // printf("ml-dsa: cleanup function called\n");
}	/* optional */

int
ssh_ml_dsa_equal(
    const struct sshkey *a,
    const struct sshkey *b
) {
    // printf("ml-dsa: equal function called\n");
    return SSH_ERR_INTERNAL_ERROR;
}

int
ssh_ml_dsa_serialize_public(
    const struct sshkey *key,
    struct sshbuf *buffer, 
    enum sshkey_serialize_rep options
) {
    int r = SSH_ERR_INTERNAL_ERROR;
    if (key->pkey == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    uint8_t pub[1312];
    size_t pub_len;
    if (!EVP_PKEY_get_octet_string_param(key->pkey, "pub", pub, sizeof(pub), &pub_len)) {
        // printf("ml-dsa: failed getting public key from key->pkey\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    if ((r = sshbuf_put_string(buffer, pub, pub_len)) != 0) {
        // printf("ml-dsa: failed moving public key to sshbuffer\n");
        return r;
    }

    return 0;
}

int
ssh_ml_dsa_deserialize_public(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    // printf("ml-dsa: deserialize public function called\n");
    return SSH_ERR_INTERNAL_ERROR;
}

int
ssh_ml_dsa_serialize_private(
    const struct sshkey *key,
    struct sshbuf *buffer,
    enum sshkey_serialize_rep options
) {
    // printf("ml-dsa: serialize private function called\n");
    int r = SSH_ERR_INTERNAL_ERROR;
    uint8_t private[2560];
    size_t priv_len;
    if (!EVP_PKEY_get_octet_string_param(key->pkey, "priv", private, sizeof(private), &priv_len)) {
        // printf("ml-dsa: failed getting private key from key->pkey\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    if ((r = sshbuf_put_string(buffer, private, priv_len)) != 0) {
        // printf("ml-dsa: failed moving private key to sshbuffer\n");
        return r;
    }

    return 0;
}

int
ssh_ml_dsa_deserialize_private(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    // printf("ml-dsa: deserialize private function called\n");
    return SSH_ERR_INTERNAL_ERROR;
}

int
ssh_ml_dsa_generate(
    struct sshkey *key, 
    int bits
) {
    // printf("ml-dsa: starting key generation\n");
    EVP_PKEY *res = NULL;
    
    if ((res = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44")) == NULL) {
		// Failed key generation so reuturn error
        // printf("ml-dsa: failed to generate key pair\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    // printf("ml-dsa: successfull key generation. Saving key\n");
    key->pkey = res;
	return 0;
}

int
ssh_ml_dsa_copy_public(
    const struct sshkey *from,
    struct sshkey *to
) {
    // printf("ml-dsa: copy public key\n");
    EVP_PKEY *new = NULL;
    // TODO: Make size dependend on the ML-DSA security level and properly free the memory as well
    uint8_t pub[1312];
    size_t pub_len;
    if (!EVP_PKEY_get_octet_string_param(from->pkey, "pub", pub, sizeof(pub), &pub_len)) {
        // printf("ml-dsa: failed getting public key from key->pkey\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    if ((new = EVP_PKEY_new_raw_public_key(EVP_PKEY_ML_DSA_44, NULL, pub, pub_len)) == NULL) {
        // printf("ml-dsa: failed creating new public key from the public key data\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    to->pkey = new;
    return 0;
}

int
ssh_ml_dsa_sign(
    struct sshkey *key,
    u_char **sigp,
    size_t *lenp,
    const u_char *data,
    size_t datalen, 
    const char *alg, 
    const char *sk_provider, 
    const char *sk_pin, 
    u_int compat
) {
    // printf("ml-dsa: sign function called\n");
    return SSH_ERR_INTERNAL_ERROR;
} /* optional */

int
ssh_ml_dsa_verify(
    const struct sshkey *key,
    const u_char *sig, 
    size_t siglen,
    const u_char *data, 
    size_t datalen, 
    const char *alg, 
    u_int compat,
    struct sshkey_sig_details **detailsp
) {
    // printf("ml-dsa: verify function called\n");
    return SSH_ERR_INTERNAL_ERROR;
}

static const struct sshkey_impl_funcs sshkey_ml_dsa_funcs = {
    // If a function has not been implemented yet, it always
    // return SSH_ERR_INTERNAL_ERROR as this avoids segfaults
	/* .size = */		ssh_ml_dsa_size,
	/* .alloc = */		ssh_ml_dsa_alloc,
	/* .cleanup = */	ssh_ml_dsa_cleanup,
	/* .equal = */		ssh_ml_dsa_equal,
	/* .ssh_serialize_public = */ ssh_ml_dsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ml_dsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ml_dsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ml_dsa_deserialize_private,
	/* .generate = */	ssh_ml_dsa_generate,
	/* .copy_public = */	ssh_ml_dsa_copy_public,
	/* .sign = */		ssh_ml_dsa_sign,
	/* .verify = */		ssh_ml_dsa_verify,
};

const struct sshkey_impl sshkey_ml_dsa_impl = {
	/* .name = */		"ssh-ml-dsa",
	/* .shortname = */	"ML-DSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ML_DSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ml_dsa_funcs,
};
#endif /* WITH_OPENSSL */