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
    debug3_f("ml-dsa: size function called");
    if (key->pkey == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    
    return EVP_PKEY_get_security_category(key->pkey);
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
    debug3_f("ml-dsa: cleanup function called");
    EVP_PKEY_free(key->pkey);
    key->pkey = NULL;
}	/* optional */

int
ssh_ml_dsa_equal(
    const struct sshkey *a,
    const struct sshkey *b
) {
    debug3_f("ml-dsa: equal function called\n");
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

    uint8_t *pub = NULL;
    size_t pub_len;
    
    // TODO: Check if EVP_PKEY_get_raw_public_key could be used instead
    // Seems to be the appropriate function to call here instead of this
    if (!EVP_PKEY_get_octet_string_param(key->pkey, "pub", pub, sizeof(pub), &pub_len)) {
        debug3_f("ml-dsa: failed getting size of public key buffer\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }
    
    pub = malloc(pub_len);
    if (!EVP_PKEY_get_octet_string_param(key->pkey, "pub", pub, pub_len, &pub_len)) {
        debug3_f("ml-dsa: failed getting public key data\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((r = sshbuf_put_string(buffer, pub, pub_len)) != 0) {
        debug3_f("failed putting key data into sshbuf");  
        goto out;
    }

    // success
    r = 0;

  out:
    free(pub);
    return r;
}

int
ssh_ml_dsa_deserialize_public(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    debug3_f("ml-dsa: deserialize public function called");
    uint8_t *pub;
    size_t pub_len;
    u_int32_t length;
    EVP_PKEY *new = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;
    
    // Read fist 4 bytes as the key length and use that to check keytype, create pub buffer, etc.
    if ((r = sshbuf_get_u32(buffer, &length)) != 0) {
        debug3_f("failed getting public key length");
        return r;
    }

    pub_len = (size_t)length;
    pub = malloc(pub_len);
    
    // sshbuf_get_string does not properly get the value from the buffer so this is a little hack to make it work.
    // sshbuf_put_string works fine, so it is kind of weird
    const u_char *p = sshbuf_ptr(buffer);
    memcpy(pub, p, pub_len);
    sshbuf_consume(buffer, pub_len); // Tell the buffer you have read its contents

    int type = 0;
    switch (pub_len) { // Key lengths from FIPS 204 standard document
        case 1312:
            type = EVP_PKEY_ML_DSA_44;
            break;
        
        case 1952:
            type = EVP_PKEY_ML_DSA_65;
            break;
        
        case 2592:
            type = EVP_PKEY_ML_DSA_87;
            break;
        
        default: // Should never happen but just in case
            r = SSH_ERR_INTERNAL_ERROR;
            break;
    }

    if (r != 0) {
        goto out;
    }

    debug3_f("creating new public key from raw key data");
    if ((new = EVP_PKEY_new_raw_public_key(type, NULL, pub, pub_len)) == NULL) {
        debug3_f("ml-dsa: failed creation of EVP_PKEY from data");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    // Success
    r = 0;
    key->pkey = new;

  out:
    free(pub);
    return r;
}

int
ssh_ml_dsa_serialize_private(
    const struct sshkey *key,
    struct sshbuf *buffer,
    enum sshkey_serialize_rep options
) {
    debug3_f("ml-dsa: serialize private function called");
    int r = SSH_ERR_INTERNAL_ERROR;
    uint8_t *private = NULL;
    size_t priv_len;
    
    // If the buffer priv is NULL then *len is populated with the number of bytes required to hold the key
    if (!EVP_PKEY_get_raw_private_key(key->pkey, private, &priv_len)) {
        debug3_f("ml-dsa: failed getting private key length");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }
    
    private = malloc(priv_len);
    if (!EVP_PKEY_get_raw_private_key(key->pkey, private, &priv_len)) {
        debug3_f("ml-dsa: failed getting pricate key data");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((r = sshbuf_put_string(buffer, private, priv_len)) != 0) {
        debug3_f("failed putting key data into sshbuf");
        goto out;
    }

    // Success
    r = 0;
  out:
    free(private);
    return r;
}

int
ssh_ml_dsa_deserialize_private(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    debug3_f("ml-dsa: deserialize private function called");
    uint8_t *private;
    size_t private_len;
    u_int32_t length;
    EVP_PKEY *new = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;

    // Read fist 4 bytes as the key length and use that to check keytype, create pub buffer, etc.
    if ((r = sshbuf_get_u32(buffer, &length)) != 0) {
        debug3_f("failed getting private key length");
        return r;
    }

    private_len = (size_t)length;
    private = malloc(private_len);

    // sshbuf_get_string does not properly get the value from the buffer so this is a little hack to make it work.
    // sshbuf_put_string works fine, so it is kind of weird
    const u_char *p = sshbuf_ptr(buffer);
    memcpy(private, p, private_len);
    sshbuf_consume(buffer, private_len); // Tell the buffer you have read its contents

    int type = 0;
    switch (private_len) { // Key lengths from FIPS 204 standard document
        case 2560:
            type = EVP_PKEY_ML_DSA_44;
            break;
        
        case 4032:
            type = EVP_PKEY_ML_DSA_65;
            break;
        
        case 4896:
            type = EVP_PKEY_ML_DSA_87;
            break;
        
        default: // Should never happen but just in case
            r = SSH_ERR_INTERNAL_ERROR;
            break;
    }

    if (r != 0) {
        goto out;
    }

    if ((new = EVP_PKEY_new_raw_private_key(type, NULL, private, private_len)) == NULL) {
        debug3_f("ml-dsa: failed creating of EVP_PKEY from data");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    // Success
    r = 0;
    key->pkey = new;
  
  out:
    free(private);
    return r;
}

int
ssh_ml_dsa_generate(
    struct sshkey *key, 
    int bits
) {
    debug3_f("ml-dsa: starting key generation\n");
    EVP_PKEY *res = NULL;
    char *key_type;
    switch (bits) {
        case 0: // Default value.
        case 44:
            key_type = "ML-DSA-44";
            break;
        case 65:
            key_type = "ML-DSA-65";
            break;
        case 87:
            key_type = "ML-DSA-87";
            break;
        
        default:
            return SSH_ERR_INVALID_ARGUMENT;
    }
    
    
    if ((res = EVP_PKEY_Q_keygen(NULL, NULL, key_type)) == NULL) {
		// Failed key generation so return error
        debug3_f("ml-dsa: failed to generate key pair\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    debug3_f("ml-dsa: successfull key generation. Saving key\n");
    key->pkey = res;
	return 0;
}

int
ssh_ml_dsa_copy_public(
    const struct sshkey *from,
    struct sshkey *to
) {
    debug3_f("ml-dsa: copy public key\n");
    EVP_PKEY *new = NULL;
    // TODO: Make size dependend on the ML-DSA security level and properly free the memory as well
    uint8_t pub[1312];
    size_t pub_len;
    if (!EVP_PKEY_get_octet_string_param(from->pkey, "pub", pub, sizeof(pub), &pub_len)) {
        debug3_f("ml-dsa: failed getting public key from key->pkey\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    if ((new = EVP_PKEY_new_raw_public_key(EVP_PKEY_ML_DSA_44, NULL, pub, pub_len)) == NULL) {
        debug3_f("ml-dsa: failed creating new public key from the public key data\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    to->pkey = new;
    return 0;
}

int
ssh_ml_dsa_encode_store_sig(
    const u_char *sig,
    size_t sig_len,
    u_char **sigp,
    size_t *lenp,
    char *alg
) {
    struct sshbuf *b = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;
    size_t len;

    // Encode signature
    if ((b = sshbuf_new()) == NULL) {
        debug3_f("ml-dsa: encoding buffer allocation failed\n");
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    if ((r = sshbuf_put_cstring(b, alg)) != 0 ||
	    (r = sshbuf_put_string(b, sig, sig_len)) != 0) {
            debug3_f("ml-dsa: Failed putting signature in buffer\n");
            goto out;
        }
    len = sshbuf_len(b);

    // Store signature
    if (sigp != NULL) {
        if ((*sigp = malloc(len)) == NULL) {
            r = SSH_ERR_ALLOC_FAIL;
            goto out;
        }
        memcpy(*sigp, sshbuf_ptr(b), len);
    }
    if (lenp != NULL)
        *lenp = len;
    
    r = 0;

  out:
    sshbuf_free(b);
    return r;
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
    char *signature_type = NULL;
    EVP_PKEY_CTX *sctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    int type = -1;
    int r = SSH_ERR_INTERNAL_ERROR;
    debug3_f("Siging using ml-dsa\n");

    if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;
    
    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string("context-string", (u_char *) "A context string", 16),
        OSSL_PARAM_END
    };

    if ((sctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL)) == NULL) {
        debug3_f("ml-dsa: failed creating context from pkey\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    type = ssh_ml_dsa_size(key);
    switch (type) { // Numbers are the FIPS 204 Security parameter set numbers
        case 2:
            signature_type = "ML-DSA-44";
            break;
        case 3:
            signature_type = "ML-DSA-65";
            break;
        case 5:
            signature_type = "ML-DSA-87";
            break;
    
        default: // some error has happened
            debug3_f("not possible to get parameter set for given ml-dsa key");
            r = SSH_ERR_LIBCRYPTO_ERROR;
            goto out;
    }

    
    if ((sig_alg = EVP_SIGNATURE_fetch(NULL, signature_type, NULL)) == NULL) {
        debug3_f("ml-dsa: failed fetching signature algorithm\n");
        r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
        goto out;
    }

    if (!(r = EVP_PKEY_sign_message_init(sctx, sig_alg, params))) {
        debug3_f("ml-dsa: message signature initialization failed\n");
        if (r == -2) {
            r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
        }
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }
    
    if (!EVP_PKEY_sign(sctx, NULL, &sig_len, data, datalen)) {
        debug3_f("ml-dsa: failed fetching signature length\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    sig = OPENSSL_zalloc(sig_len);
    if (!EVP_PKEY_sign(sctx, sig, &sig_len, data, datalen)) {
        debug3_f("ml-dsa: failed siging the message\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((r = ssh_ml_dsa_encode_store_sig(sig, sig_len, sigp, lenp, signature_type)) != 0) {
        debug3_f("ml-dsa: signature encoding/storing failed\n");
        goto out;
    }
    
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
    u_char *signature;
    char *signature_type = NULL;
    struct sshbuf *b = NULL;
    debug3_f("Verifying signature for ml-dsa\n");
    
    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string("context-string", (u_char *) "A context string", 16),
        OSSL_PARAM_END
    };
    
    if ((b = sshbuf_from(sig, siglen)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    if (sshbuf_get_cstring(b, &signature_type, NULL) != 0) {
        debug3_f("ml-dsa: Failed getting signature type from buffer\n");
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }
    
    if (sshbuf_get_string(b, &signature, &siglen) != 0) {
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }
    
    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL)) == NULL) {
        debug3_f("ml-dsa: failed creating context from pkey\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }
    
    if ((sig_alg = EVP_SIGNATURE_fetch(NULL, signature_type, NULL)) == NULL) {
        debug3_f("ml-dsa: failed fetching signature algorithm\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if (!EVP_PKEY_verify_message_init(ctx, sig_alg, params)) {
        debug3_f("ml-dsa: Context initialization failed\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }
    
    if (!EVP_PKEY_verify(ctx, signature, siglen, data, datalen)) {
        debug3_f("ml-dsa: failed signature verification\n");
        r = SSH_ERR_SIGNATURE_INVALID;
        goto out;
    }

    // Success
    r = 0;
    
  out:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_CTX_free(ctx);
    sshbuf_free(b);
    free(signature_type);
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

const struct sshkey_impl sshkey_ml_dsa_cert_impl = {
	/* .name = */		"ssh-ml-dsa-cert",
	/* .shortname = */	"ML-DSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ML_DSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ml_dsa_funcs,
};
#endif /* WITH_OPENSSL */