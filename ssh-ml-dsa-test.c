#include <stdio.h>
#include <stdint.h>
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "ssh-ml-dsa.h"

int generate_key(struct sshkey *key) {
    return ssh_ml_dsa_generate(key, 0);
}

int equals_works(struct sshkey *key) {
    return ssh_ml_dsa_equal(key, key) != 1;
}

int serialize_deserialize_pub_eq(struct sshkey *key) {
    int r = 0;
    struct sshbuf *serialization_buffer = sshbuf_new();
    struct sshkey *deserialized = sshkey_new(KEY_ML_DSA);
    r = ssh_ml_dsa_serialize_public(key, serialization_buffer, SSHKEY_SERIALIZE_DEFAULT);
    if (r != 0) {
        printf("serialization failed for public key\n");
        goto out;
    }
    r = ssh_ml_dsa_deserialize_public("ml-dsa", serialization_buffer, deserialized);
    if (r != 0) {
        printf("deserialization failed for public key\n");
        goto out;
    }

    r = ssh_ml_dsa_equal(key, deserialized) != 1;

  out:
    sshbuf_free(serialization_buffer);
    sshkey_free(deserialized);
    return r;
}

int serialize_deserialize_priv_eq(struct sshkey *key) {
    int r = 0;
    struct sshbuf *serialization_buffer = sshbuf_new();
    struct sshkey *deserialized = sshkey_new(KEY_ML_DSA);
    r = ssh_ml_dsa_serialize_private(key, serialization_buffer, SSHKEY_SERIALIZE_DEFAULT);
    if (r != 0) {
        printf("serialization failed for private key\n");
        goto out;
    }
    // printf("buffer length: %d\n", sshbuf_len(serialization_buffer));
    r = ssh_ml_dsa_deserialize_private("ml-dsa", serialization_buffer, deserialized);
    if (r != 0) {
        printf("deserialization failed for private key\n");
        goto out;
    }

    r = ssh_ml_dsa_equal(key, deserialized) != 1;

  out:
    sshbuf_free(serialization_buffer);
    sshkey_free(deserialized);
    return r;
}


int main(void) {
    int r = SSH_ERR_INTERNAL_ERROR;
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    r = generate_key(key);
    if (r != 0) {
        printf("FAILED KEY GENERATION\n");
        goto out;
    }
    
    r = equals_works(key);
    if (r != 0) {
        printf("equal does not work: %d\n", r);
        goto out;
    }
    
    r = serialize_deserialize_pub_eq(key);
    if (r != 0) {
        printf("Serialization then deserialization public key is not equal\n");
        goto out;
    }
    
    r = serialize_deserialize_priv_eq(key);
    if (r != 0) {
        printf("Serialization then deserialization private key is not equal\n");
        goto out;
    }
    
    r = serialize_deserialize_priv_eq(key);
    if (r != 0) {
        printf("Serialization then deserialization private key is not equal\n");
        goto out;
    }

  out:
    sshkey_free(key);
}