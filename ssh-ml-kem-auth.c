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
ssh_ml_kem_auth_size(
    const struct sshkey *key
) {
    if (key->pkey == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    
    return EVP_PKEY_get_security_category(key->pkey);
}

int 
ssh_ml_kem_auth_alloc(
    struct sshkey *key
) {
    if ((key->pkey = EVP_PKEY_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	return 0;
}

void
ssh_ml_kem_auth_cleanup(
    struct sshkey *key
) {
    EVP_PKEY_free(key->pkey);
    key->pkey = NULL;
}

int
ssh_ml_kem_auth_equal(
    const struct sshkey *a,
    const struct sshkey *b
) {
    if (a->pkey == NULL || b->pkey == NULL) {
        return 0;
    }
    return EVP_PKEY_eq(a->pkey, b->pkey) == 1;
}

int
ssh_ml_kem_auth_serialize_public(
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
    
    if (!EVP_PKEY_get_raw_public_key(key->pkey, pub, &pub_len)) {
        fprintf(stderr, "failed getting size of public key buffer\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }
    
    pub = malloc(pub_len);
    if (!EVP_PKEY_get_raw_public_key(key->pkey, pub, &pub_len)) {
        fprintf(stderr, "failed getting public key data\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((r = sshbuf_put_string(buffer, pub, pub_len)) != 0) {
        fprintf(stderr, "failed putting key data into sshbuf\n");  
        goto out;
    }

    // success
    r = 0;

  out:
    free(pub);
    return r;
}

int
ssh_ml_kem_auth_deserialize_public(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    uint8_t *pub;
    size_t pub_len;
    u_int32_t length;
    EVP_PKEY *new = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;
    
    // Read fist 4 bytes as the key length and use that to check keytype, create pub buffer, etc.
    if ((r = sshbuf_get_u32(buffer, &length)) != 0) {
        fprintf(stderr, "failed getting public key length\n");
        return r;
    }

    pub_len = (size_t)length;
    pub = malloc(pub_len);
    
    // sshbuf_get_string does not properly get the value from the buffer so this is a little hack to make it work.
    // sshbuf_put_string works fine, so it is kind of weird
    const u_char *p = sshbuf_ptr(buffer);
    memcpy(pub, p, pub_len);
    sshbuf_consume(buffer, pub_len); // Tell the buffer you have read its contents

    char *type = NULL;
    switch (pub_len) { // Key lengths from FIPS 203 document
        case 800:
            type = "ML-KEM-512";
            break;
        case 1184:
            type = "ML-KEM-768";
            break;
        case 1568:
            type = "ML-KEM-1024";
            break;
        default: // Should never happen as pub_len is fetched from Openssl
            r = SSH_ERR_INTERNAL_ERROR;
            goto out;
    }

    if ((new = EVP_PKEY_new_raw_public_key_ex(NULL, type, NULL, pub, pub_len)) == NULL) {
        fprintf(stderr, "failed creation of EVP_PKEY from data\n");
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
ssh_ml_kem_auth_serialize_private(
    const struct sshkey *key,
    struct sshbuf *buffer,
    enum sshkey_serialize_rep options
) {
    int r = SSH_ERR_INTERNAL_ERROR;
    uint8_t *private = NULL;
    size_t priv_len;
    
    // If the buffer priv is NULL then *len is populated with the number of bytes required to hold the key
    if (!EVP_PKEY_get_raw_private_key(key->pkey, private, &priv_len)) {
        fprintf(stderr, "failed getting private key length\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }
    
    private = malloc(priv_len);
    if (!EVP_PKEY_get_raw_private_key(key->pkey, private, &priv_len)) {
        fprintf(stderr, "failed getting pricate key data\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((r = sshbuf_put_string(buffer, private, priv_len)) != 0) {
        fprintf(stderr, "failed putting key data into sshbuf\n");
        goto out;
    }

    // Success
    r = 0;
  out:
    free(private);
    return r;
}

int
ssh_ml_kem_auth_deserialize_private(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    uint8_t *private;
    size_t private_len;
    u_int32_t length;
    EVP_PKEY *new = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;

    // Read fist 4 bytes as the key length and use that to check keytype, create pub buffer, etc.
    if ((r = sshbuf_get_u32(buffer, &length)) != 0) {
        fprintf(stderr, "failed getting private key length\n");
        return r;
    }

    private_len = (size_t)length;
    private = malloc(private_len);

    // sshbuf_get_string does not properly get the value from the buffer so this is a little hack to make it work.
    // sshbuf_put_string works fine, so it is kind of weird
    const u_char *p = sshbuf_ptr(buffer);
    memcpy(private, p, private_len);
    sshbuf_consume(buffer, private_len); // Tell the buffer you have read its contents

    char *type = NULL;
    switch (private_len) { // Key lengths from FIPS 204 standard document
        case 1632:
            type = "ML-KEM-512";
            break;
        
        case 2400:
            type = "ML-KEM-768";
            break;
        
        case 3168:
            type = "ML-KEM-1024";
            break;
        
        default: // Should never happen but just in case
            r = SSH_ERR_INTERNAL_ERROR;
            goto out;
    }

    if ((new = EVP_PKEY_new_raw_private_key_ex(NULL, type, NULL, private, private_len)) == NULL) {
        fprintf(stderr, "failed creating of EVP_PKEY from data\n");
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
ssh_ml_kem_auth_generate(
    struct sshkey *key, 
    int bits
) {
    EVP_PKEY *res = NULL;
    char *key_type;
    switch (bits) {
        case 0: // Default value.
        case 512:
            key_type = "ML-KEM-512";
            break;
        case 768:
            key_type = "ML-KEM-768";
            break;
        case 1024:
            key_type = "ML-KEM-1024";
            break;
        
        default:
            return SSH_ERR_INVALID_ARGUMENT;
    }
    
    
    if ((res = EVP_PKEY_Q_keygen(NULL, NULL, key_type)) == NULL) {
		// Failed key generation so return error
        fprintf(stderr, "failed to generate key pair\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    key->pkey = res;
	return 0;
}

int
ssh_ml_kem_auth_copy_public(
    const struct sshkey *from,
    struct sshkey *to
) {
    EVP_PKEY *new = NULL;
    uint8_t *pub;
    size_t pub_len;
    char *type = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;
    
    // The required buffer size can be obtained from *out_len by calling the function with buf set to NULL
    if (!EVP_PKEY_get_octet_string_param(from->pkey, "pub", NULL, 0, &pub_len)) {
        fprintf(stderr, "failed getting public key size from key->pkey\n");
        return SSH_ERR_LIBCRYPTO_ERROR;
    }
    
    pub = malloc(pub_len);
    // The required buffer size can be obtained from *out_len by calling the function with buf set to NULL
    if (!EVP_PKEY_get_octet_string_param(from->pkey, "pub", pub, pub_len, &pub_len)) {
        fprintf(stderr, "failed getting public key size from key->pkey\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    switch (pub_len) { // Key lengths from FIPS 203 document
        case 800:
            type = "ML-KEM-512";
            break;
        case 1184:
            type = "ML-KEM-768";
            break;
        case 1568:
            type = "ML-KEM-1024";
            break;
        default: // Should never happen as pub_len is fetched from Openssl
            r = SSH_ERR_INTERNAL_ERROR;
            goto out;
    }

    if ((new = EVP_PKEY_new_raw_public_key_ex(NULL, type, NULL, pub, pub_len)) == NULL) {
        fprintf(stderr, "failed creating new public key from the public key data\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    // Success
    r = 0;
    to->pkey = new;

  out:
    free(pub);
    return r;
}

int
ssh_ml_kem_auth_encapsulate(
    struct sshkey *key,
    u_char **ct_ptr,
    size_t *lenp,
    const u_char *ss,
    size_t ss_len, 
    const char *alg, 
    const char *sk_provider, 
    const char *sk_pin, 
    u_int compat
) {
    size_t ct_len;
    u_char *ct = NULL;
    size_t ossl_ss_len;
    EVP_PKEY_CTX *encaps_ctx = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;

    if (ss == NULL) {
        fprintf(stderr, "shared secret is NULL!\n");
        return SSH_ERR_INVALID_ARGUMENT;
    }
    
    if (lenp != NULL)
		*lenp = 0;
	if (ct_ptr != NULL)
		*ct_ptr = NULL;

    if ((encaps_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL)) == NULL) {
        fprintf(stderr, "failed generating encapsulation context from key\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }
    
    if ((r = EVP_PKEY_encapsulate_init(encaps_ctx, NULL)) <= 0) {
        fprintf(stderr, "failed initializing encapsulation context\n");
        r = r == -2 ? SSH_ERR_SIGN_ALG_UNSUPPORTED : SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    // Get maximum size of ct and ss buffers
    if ((r = EVP_PKEY_encapsulate(encaps_ctx, ct, &ct_len, NULL, &ossl_ss_len)) <= 0) {
        fprintf(stderr, "failed getting ct_len and ss_len\n");
        r = r == -2 ? SSH_ERR_SIGN_ALG_UNSUPPORTED : SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if (ossl_ss_len > ss_len) {
        fprintf(stderr, "shared secret buffer is not big enough");
        r = SSH_ERR_INVALID_ARGUMENT;
        goto out;
    }

    fprintf(stderr, "kem_encapsulate: ct_len: %d\n", ct_len);
    ct = malloc(ct_len);
    
    // Generate and encapsulate shared secret and save in ct and ss. Lengths are updated to reflect actual lengths.
    if ((r = EVP_PKEY_encapsulate(encaps_ctx, ct, &ct_len, ss, &ss_len)) <= 0) {
        fprintf(stderr, "failed when trying to encapsulate a shared secret\n");
        r = r == -2 ? SSH_ERR_SIGN_ALG_UNSUPPORTED : SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    // From the documentation: 
    // >> If wrappedkey (ct here) is not NULL and the call is successful then the generated shared secret
    // >> is written to genkey (ss here) and its size is written to *genkeylen (which must be non-NULL).
    if (ct == NULL) {
        fprintf(stderr, "failed call to EVP_PKEY_encapsulate\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    // All is good
    // Transfer to given ct_ptr and shared_secret
    *ct_ptr = malloc(ct_len);
    memcpy(*ct_ptr, ct, ct_len);
    *lenp = ct_len;

    // success
    r = 0;

  out:
    if (r != 0) {
        // Make sure ss is zero if an error occours to not leak anything
        memset(ss, 0, ss_len);
    }
    if (ct != NULL) {
        free(ct);
    }
    EVP_PKEY_CTX_free(encaps_ctx);
    return r;
}

int
ssh_ml_kem_auth_decapsulate(
    const struct sshkey *key,
    const u_char *ct, 
    size_t ct_len,
    u_char *ss,
    size_t ss_len,
    const char *alg, 
    u_int compat,
    struct sshkey_sig_details **detailsp
) {
    size_t ossl_ss_len = 0;
    EVP_PKEY_CTX *decaps_ctx = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;

    if (ct == NULL) {
        fprintf(stderr, "ciphertext is NULL!\n");
        return SSH_ERR_INVALID_ARGUMENT;
    }
    
    if (ss == NULL) {
        fprintf(stderr, "shared secret is NULL!\n");
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if ((decaps_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL)) == NULL) {
        fprintf(stderr, "failed generating decapsulation context from key\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }
    
    if ((r = EVP_PKEY_decapsulate_init(decaps_ctx, NULL)) <= 0) {
        fprintf(stderr, "failed initializing decapsulation context\n");
        r = r == -2 ? SSH_ERR_SIGN_ALG_UNSUPPORTED : SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    // Get maximum size and ss buffer
    if ((r = EVP_PKEY_decapsulate(decaps_ctx, NULL, &ossl_ss_len, ct, ct_len)) <= 0) {
        fprintf(stderr, "failed getting ss_len: %d\n", r);
        r = r == -2 ? SSH_ERR_SIGN_ALG_UNSUPPORTED : SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if (ossl_ss_len > ss_len) {
        fprintf(stderr, "shared secret buffer is not big enough");
        r = SSH_ERR_INVALID_ARGUMENT;
        goto out;
    }
    
    // Decapsulate ct into ss
    if ((r = EVP_PKEY_decapsulate(decaps_ctx, ss, &ss_len, ct, ct_len)) <= 0) {
        fprintf(stderr, "failed when trying to decapsulate a shared secret: %d\n", r);
        r = r == -2 ? SSH_ERR_SIGN_ALG_UNSUPPORTED : SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }
    // success
    r = 0;

  out:
    EVP_PKEY_CTX_free(decaps_ctx);
    return r;
}

static const struct sshkey_impl_funcs sshkey_ml_kem_auth_funcs = {
    // If a function has not been implemented yet, it always
    // return SSH_ERR_INTERNAL_ERROR as this avoids segfaults
	/* .size = */		ssh_ml_kem_auth_size,
	/* .alloc = */		ssh_ml_kem_auth_alloc,
	/* .cleanup = */	ssh_ml_kem_auth_cleanup,
	/* .equal = */		ssh_ml_kem_auth_equal,
	/* .ssh_serialize_public = */ ssh_ml_kem_auth_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ml_kem_auth_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ml_kem_auth_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ml_kem_auth_deserialize_private,
	/* .generate = */	ssh_ml_kem_auth_generate,
	/* .copy_public = */	ssh_ml_kem_auth_copy_public,
	/* .sign = */		ssh_ml_kem_auth_encapsulate,
	/* .verify = */		ssh_ml_kem_auth_decapsulate,
};

const struct sshkey_impl sshkey_ml_kem_auth_impl = {
	/* .name = */		"ssh-ml-kem-auth",
	/* .shortname = */	"ML-KEM-AUTH",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ML_KEM_AUTH,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ml_kem_auth_funcs,
};

#endif /* WITH_OPENSSL */