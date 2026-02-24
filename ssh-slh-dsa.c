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
#ifndef SSH_SLH_DSA_H
#define SSH_SLH_DSA_H


#include "includes.h"

#ifdef WITH_OPEN_QUANTUM_SAFE
#include <sys/types.h>
#include <oqs/oqs.h>
#include <oqs/sig_slh_dsa.h>

#include "openbsd-compat/openssl-compat.h"

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "log.h"

u_int
ssh_slh_dsa_size(
    const struct sshkey *key
) {
    if (key->oqs_sig == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    return key->oqs_sig->length_public_key;
}

int 
ssh_slh_dsa_alloc(
    struct sshkey *key
) {
    return 0;
}

void
ssh_slh_dsa_cleanup(
    struct sshkey *key
) {

}

int
ssh_slh_dsa_equal(
    const struct sshkey *a,
    const struct sshkey *b
) {
    if (a->oqs_sig == NULL || b->oqs_sig == NULL) {
        fprintf(stderr, "oqs_sig is null for at least one\n");
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (a->oqs_sig->length_public_key != b->oqs_sig->length_public_key) {
        fprintf(stderr, "pub key lengths not the same\n");
        return 0;
    }
    debug3_f("calling memcmp");
    return memcmp(a->slh_dsa_pk, b->slh_dsa_pk, a->oqs_sig->length_public_key) == 0;
}

int
ssh_slh_dsa_serialize_public(
    const struct sshkey *key,
    struct sshbuf *buffer, 
    enum sshkey_serialize_rep options
) {
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = sshbuf_put_string(buffer, key->oqs_sig->method_name, strlen(key->oqs_sig->method_name) + 1)) != 0) {
        fprintf(stderr, "failed putting method name into sshbuf\n");
        return r;
    }

    if ((r = sshbuf_put_string(buffer, key->slh_dsa_pk, key->oqs_sig->length_public_key)) != 0) {
        fprintf(stderr, "failed putting public key data into sshbuf\n");
        return r;
    }
    
    // Success
    return 0;
}

int
ssh_slh_dsa_deserialize_public(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    u_int32_t length;
    size_t length_method_name;
    size_t length_public_key;
    char *method_name;
    const u_char *buf_ptr;
    int r = SSH_ERR_INTERNAL_ERROR;

    if ((r = sshbuf_get_u32(buffer, &length)) != 0) {
        fprintf(stderr, "failed getting method name length\n");
        return r;
    }

    length_method_name = (size_t)length;
    method_name = malloc(length_method_name);
    buf_ptr = sshbuf_ptr(buffer);
    memcpy(method_name, buf_ptr, length_method_name);
    sshbuf_consume(buffer, length_method_name); // Tell the buffer you have read its contents

    if ((key->oqs_sig = OQS_SIG_new(method_name)) == NULL) {
        fprintf(stderr, "failed allocating oqs_sig\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((r = sshbuf_get_u32(buffer, &length)) != 0) {
        fprintf(stderr, "failed getting public key length\n");
        goto out;
    }

    length_public_key = (size_t)length;
    if (length_public_key != key->oqs_sig->length_public_key) {
        fprintf(stderr, "public key length mismatch\n");
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }

    if ((key->slh_dsa_pk = OQS_MEM_malloc(length_public_key)) == NULL) {
        fprintf(stderr, "failed allocating key->slh_dsa_pk\n");
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }
    buf_ptr = sshbuf_ptr(buffer);
    memcpy(key->slh_dsa_pk, buf_ptr, length_public_key);
    sshbuf_consume(buffer, length_public_key); // Tell the buffer you have read its contents


    // Success
    r = 0;
    
  out:
    free(method_name);
    if (r != 0) {
        OQS_MEM_insecure_free(key->slh_dsa_pk);
        if (key->oqs_sig != NULL) {
            // Documentation does not say it can be called on a null pointer
            // Better safe than sorry
            OQS_SIG_free(key->oqs_sig);
        }
    }
    return r;
}

int
ssh_slh_dsa_serialize_private(
    const struct sshkey *key,
    struct sshbuf *buffer,
    enum sshkey_serialize_rep options
) {
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = sshbuf_put_string(buffer, key->oqs_sig->method_name, strlen(key->oqs_sig->method_name) + 1)) != 0) {
        fprintf(stderr, "failed putting method name into sshbuf\n");
        return r;
    }

    if ((r = sshbuf_put_string(buffer, key->slh_dsa_sk, key->oqs_sig->length_secret_key)) != 0) {
        fprintf(stderr, "failed putting secret key data into sshbuf\n");
        return r;
    }
    
    // hack to allow for private keys to also know the public key.
    // Used to check it is the correct key when loading them during authentication
    if ((r = sshbuf_put_string(buffer, key->slh_dsa_pk, key->oqs_sig->length_public_key)) != 0) {
        fprintf(stderr, "failed putting public key data into sshbuf\n");
        return r;
    }
    
    // Success
    return 0;
}

int
ssh_slh_dsa_deserialize_private(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
) {
    u_int32_t length;
    size_t length_method_name;
    size_t length_secret_key;
    size_t length_public_key;
    char *method_name;
    const u_char *buf_ptr;
    int r = SSH_ERR_INTERNAL_ERROR;

    if ((r = sshbuf_get_u32(buffer, &length)) != 0) {
        fprintf(stderr, "failed getting method name length\n");
        return r;
    }

    length_method_name = (size_t)length;
    method_name = malloc(length_method_name);
    buf_ptr = sshbuf_ptr(buffer);
    memcpy(method_name, buf_ptr, length_method_name);
    sshbuf_consume(buffer, length_method_name); // Tell the buffer you have read its contents

    if ((key->oqs_sig = OQS_SIG_new(method_name)) == NULL) {
        fprintf(stderr, "failed allocating oqs_sig\n");
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((r = sshbuf_get_u32(buffer, &length)) != 0) {
        fprintf(stderr, "failed getting secret key length\n");
        goto out;
    }

    length_secret_key = (size_t)length;
    if (length_secret_key != key->oqs_sig->length_secret_key) {
        fprintf(stderr, "secret key length mismatch\n");
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }

    if ((key->slh_dsa_sk = OQS_MEM_malloc(length_secret_key)) == NULL) {
        fprintf(stderr, "failed allocating key->slh_dsa_sk\n");
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }
    buf_ptr = sshbuf_ptr(buffer);
    memcpy(key->slh_dsa_sk, buf_ptr, length_secret_key);
    sshbuf_consume(buffer, length_secret_key); // Tell the buffer you have read its contents
    
    if ((r = sshbuf_get_u32(buffer, &length)) != 0) {
        fprintf(stderr, "failed getting public key length\n");
        goto out;
    }

    length_public_key = (size_t)length;
    if (length_public_key != key->oqs_sig->length_public_key) {
        fprintf(stderr, "private_deserialize: public key length mismatch: %d != %d\n", length_public_key, key->oqs_sig->length_public_key);
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }

    if ((key->slh_dsa_pk = OQS_MEM_malloc(length_public_key)) == NULL) {
        fprintf(stderr, "failed allocating key->slh_dsa_pk during private deserialization\n");
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }
    buf_ptr = sshbuf_ptr(buffer);
    memcpy(key->slh_dsa_pk, buf_ptr, length_public_key);
    sshbuf_consume(buffer, length_public_key); // Tell the buffer you have read its contents
    

    // Success
    r = 0;
    
  out:
    free(method_name);
    if (r != 0) {
        OQS_MEM_insecure_free(key->slh_dsa_pk);
        if (key->oqs_sig != NULL) {
            // Documentation does not say it can be called on a null pointer
            // Better safe than sorry
            OQS_SIG_free(key->oqs_sig);
        }
    }
    return r;
}

int
ssh_slh_dsa_generate(
    struct sshkey *key,
    int bits
) {
    int r = SSH_ERR_INTERNAL_ERROR;
    char *type = NULL;
    switch (bits){
        case 0: // default bits
        case 128:
            type = OQS_SIG_alg_slh_dsa_pure_sha2_128s;
            break;
        case 192:
            type = OQS_SIG_alg_slh_dsa_pure_sha2_192s;
            break;
        case 256:
            type = OQS_SIG_alg_slh_dsa_pure_sha2_256s;
            break;
    
        default:
            r = SSH_ERR_INVALID_ARGUMENT;
            goto out;
    }

    if ((key->oqs_sig = OQS_SIG_new(type)) == NULL) {
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((key->slh_dsa_pk = OQS_MEM_malloc(key->oqs_sig->length_public_key)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }
	
    if ((key->slh_dsa_sk = OQS_MEM_malloc(key->oqs_sig->length_secret_key)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    if (OQS_SIG_keypair(key->oqs_sig, key->slh_dsa_pk, key->slh_dsa_sk) == OQS_ERROR) {
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }
    
    /* success */
    r = 0;

  out:
    if (r != 0) {
        OQS_MEM_insecure_free(key->slh_dsa_pk);
        if (key->oqs_sig != NULL) { 
            OQS_MEM_secure_free(key->slh_dsa_sk, key->oqs_sig->length_secret_key);
            // Documentation does not say it can be called on a null pointer
            // Better safe than sorry
            OQS_SIG_free(key->oqs_sig);
        }
    }
  
    return r;
}

int
ssh_slh_dsa_copy_public(
    const struct sshkey *from,
    struct sshkey *to
) {
    if (from->oqs_sig == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if ((to->oqs_sig = OQS_SIG_new(from->oqs_sig->method_name)) == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }

    if ((to->slh_dsa_pk = OQS_MEM_malloc(to->oqs_sig->length_public_key)) == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }

    memcpy(to->slh_dsa_pk, from->slh_dsa_pk, to->oqs_sig->length_public_key);

    return 0;
}

int 
ssh_slh_dsa_encode_store_sig(
    uint8_t *sig,
    size_t sig_len,
    u_char **sigp,
    size_t *lenp
) {
    struct sshbuf *b = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;
    size_t len;

    // Encode signature
    if ((b = sshbuf_new()) == NULL) {
        debug3_f("encoding buffer allocation failed\n");
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    if ((r = sshbuf_put_cstring(b, "ssh-slh-dsa")) != 0 ||
	    (r = sshbuf_put_string(b, sig, sig_len)) != 0) {
            debug3_f("Failed putting signature in buffer\n");
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
ssh_slh_dsa_sign(
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
    int r = SSH_ERR_INTERNAL_ERROR;
    uint8_t *sig;

    if (lenp != NULL)
		*lenp = key->oqs_sig->length_signature;
	if (sigp != NULL)
		*sigp = NULL;

    if ((sig = OQS_MEM_malloc(key->oqs_sig->length_signature)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    if (OQS_SIG_sign(key->oqs_sig, sig, lenp, data, datalen, key->slh_dsa_sk) != OQS_SUCCESS) {
        r = SSH_ERR_LIBCRYPTO_ERROR;
        goto out;
    }

    if ((r = ssh_slh_dsa_encode_store_sig(sig, key->oqs_sig->length_signature, sigp, lenp)) != 0) {
        goto out;
    }

    // Success
    r = 0;

  out:
    OQS_MEM_insecure_free(sig);
    return r;
}

int
ssh_slh_dsa_verify(
    const struct sshkey *key,
    const u_char *sig, 
    size_t siglen,
    u_char *data, 
    size_t datalen, 
    const char *alg, 
    u_int compat,
    struct sshkey_sig_details **detailsp
) {
    int r = SSH_ERR_INTERNAL_ERROR;
    u_char *signature;
    char *signature_type = NULL;
    struct sshbuf *b = NULL;

    if ((b = sshbuf_from(sig, siglen)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }
    
    if (sshbuf_get_cstring(b, &signature_type, NULL) != 0) {
        debug3_f("Failed getting signature type from buffer\n");
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }

    // Don't try to validate signatures that are not slh-dsa signatures
    if (strcmp(signature_type, "ssh-slh-dsa")) {
        r = SSH_ERR_INVALID_ARGUMENT;
        goto out;
    }

    if (sshbuf_get_string(b, &signature, &siglen) != 0) {
        r = SSH_ERR_SIGNATURE_INVALID;
        goto out;
    }

    if (OQS_SIG_verify(key->oqs_sig, data, datalen, signature, siglen, key->slh_dsa_pk) != OQS_SUCCESS) {
        r = SSH_ERR_SIGNATURE_INVALID;
        goto out;
    }

    // Success
    r = 0;

  out:
    sshbuf_free(b);
    return r;
}

static const struct sshkey_impl_funcs sshkey_slh_dsa_funcs = {
    // If a function has not been implemented yet, it always
    // return SSH_ERR_INTERNAL_ERROR as this avoids segfaults
	/* .size = */		ssh_slh_dsa_size,
	/* .alloc = */		ssh_slh_dsa_alloc,
	/* .cleanup = */	ssh_slh_dsa_cleanup,
	/* .equal = */		ssh_slh_dsa_equal,
	/* .ssh_serialize_public = */ ssh_slh_dsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_slh_dsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_slh_dsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_slh_dsa_deserialize_private,
	/* .generate = */	ssh_slh_dsa_generate,
	/* .copy_public = */	ssh_slh_dsa_copy_public,
	/* .sign = */		ssh_slh_dsa_sign,
	/* .verify = */		ssh_slh_dsa_verify,
};

const struct sshkey_impl sshkey_slh_dsa_impl = {
	/* .name = */		"ssh-slh-dsa",
	/* .shortname = */	"SLH-DSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_SLH_DSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_slh_dsa_funcs,
};

#endif /* WITH_OPEN_QUANTUM_SAFE */
#endif /* SSH_SLH_DSA_H */