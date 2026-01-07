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
);

int 
ssh_slh_dsa_alloc(
    struct sshkey *key
);

void
ssh_slh_dsa_cleanup(
    struct sshkey *key
);

int
ssh_slh_dsa_equal(
    const struct sshkey *a,
    const struct sshkey *b
);

int
ssh_slh_dsa_serialize_public(
    const struct sshkey *key,
    struct sshbuf *buffer, 
    enum sshkey_serialize_rep options
);

int
ssh_slh_dsa_deserialize_public(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
);

int
ssh_slh_dsa_serialize_private(
    const struct sshkey *key,
    struct sshbuf *buffer,
    enum sshkey_serialize_rep options
);

int
ssh_slh_dsa_deserialize_private(
    const char *key_type, 
    struct sshbuf *buffer, 
    struct sshkey *key
);

int
ssh_slh_dsa_generate(
    struct sshkey *key, 
    int bits
);

int
ssh_slh_dsa_copy_public(
    const struct sshkey *from,
    struct sshkey *to
);

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
);

int
ssh_slh_dsa_verify(
    const struct sshkey *key,
    const u_char *sig, 
    size_t siglen,
    const u_char *data, 
    size_t datalen, 
    const char *alg, 
    u_int compat,
    struct sshkey_sig_details **detailsp
);

#endif /* WITH_OPEN_QUANTUM_SAFE */
#endif /* SSH_SLH_DSA_H */