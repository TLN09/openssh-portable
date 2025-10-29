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
#include <openssl/core.h>

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
    if (a->pkey == NULL || b->pkey == NULL) {
        return 0;
    }
    return EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
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

   for (int i = 0; i < pub_len; i++) {
        r = sshbuf_put_u8(buffer, pub[i]);
        // // printf("%x", pub[i]);
    }

    return 0;
}

int
ssh_ml_dsa_deserialize_public(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    // TODO: Take keytype into consideration
    // printf("ml-dsa: deserialize public function called\n");
    uint8_t pub[1312];
    size_t pub_len = sizeof(pub);
    EVP_PKEY *new = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;
    for (int i = 0; i < pub_len; i++) {
        sshbuf_get_u8(buffer, &pub[i]);
        // // printf("%x", pub[i]);
    }

    if ((new = EVP_PKEY_new_raw_public_key(EVP_PKEY_ML_DSA_44, NULL, pub, pub_len)) == NULL) {
        // printf("ml-dsa: failed creation of EVP_PKEY from data\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    key->pkey = new;
    return 0;
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
    size_t priv_len = sizeof(private);
    
    if (!EVP_PKEY_get_raw_private_key(key->pkey, private, &priv_len)) {
        // printf("ml-dsa: failed getting private key data from key->pkey\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }
    for (int i = 0; i < priv_len; i++) {
        sshbuf_put_u8(buffer, private[i]);
        // // printf("%x", private[i]);
    }

    return 0;
}

int
ssh_ml_dsa_deserialize_private(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    // printf("ml-dsa: deserialize private function called with type: %s\n", key_type);
    // TODO: Take keytype into consideration
    uint8_t private[2560];
    size_t private_len = sizeof(private);
    EVP_PKEY *new = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;

    for (int i = 0; i < private_len; i++) {
        sshbuf_get_u8(buffer, &private[i]);
        // // printf("%x", private[i]);
    }
    // // printf("\n");

    if ((new = EVP_PKEY_new_raw_private_key(EVP_PKEY_ML_DSA_44, NULL, private, sizeof(private))) == NULL) {
        // printf("ml-dsa: failed creating of EVP_PKEY from data\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    key->pkey = new;
    return 0;
}

int
ssh_ml_dsa_generate(
    struct sshkey *key, 
    int bits
) {
    // printf("ml-dsa: starting key generation\n");
    EVP_PKEY *res = NULL;
    
    if ((res = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44")) == NULL) {
		// Failed key generation so return error
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
    size_t sig_len;
    u_char *sig = NULL;
    EVP_PKEY_CTX *sctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;

    if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;
    
    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string("context-string", (u_char *) "A context string", 16),
        OSSL_PARAM_END
    };

    if ((sctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL)) == NULL) {
        printf("ml-dsa: failed creating context from pkey\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((sig_alg = EVP_SIGNATURE_fetch(NULL, "ML-DSA-44", NULL)) == NULL) {
        printf("ml-dsa: failed fetching signature algorithm\n");
        r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
        goto out;
    }

    if (!(r = EVP_PKEY_sign_message_init(sctx, sig_alg, params))) {
        printf("ml-dsa: message signature initialization failed\n");
        if (r == -2) {
            r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
        }
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }
    
    if (!EVP_PKEY_sign(sctx, NULL, &sig_len, data, datalen)) {
        printf("ml-dsa: failed fetching signature length\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    sig = OPENSSL_zalloc(sig_len);
    if (!EVP_PKEY_sign(sctx, sig, &sig_len, data, datalen)) {
        printf("ml-dsa: failed siging the message\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    *lenp = sig_len;
    *sigp = malloc(sig_len);
    memcpy(*sigp, sig, sig_len);
    
    // Success
    r = 0;

  out:
    OPENSSL_free(sig);
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_CTX_free(sctx);
    return r;
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
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;
    
    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string("context-string", (u_char *) "A context string", 16),
        OSSL_PARAM_END
    };

    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL)) == NULL) {
        printf("ml-dsa: failed creating context from pkey\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((sig_alg = EVP_SIGNATURE_fetch(NULL, "ML-DSA-44", NULL)) == NULL) {
        printf("ml-dsa: failed fetching signature algorithm\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if (!EVP_PKEY_verify_message_init(ctx, sig_alg, params)) {
        printf("ml-dsa: Context initialization failed\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }
    
    if (!EVP_PKEY_verify(ctx, sig, siglen, data, datalen)) {
        printf("ml-dsa: failed signature verification\n");
        r = SSH_ERR_SIGNATURE_INVALID;
        goto out;
    }

    // Success
    r = 0;
    
  out:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_CTX_free(ctx);
    return r;
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