#include <stdio.h>
#include <stdint.h>
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "ssh-ml-dsa.h"

int generate_key(struct sshkey *key) {
    return ssh_ml_dsa_generate(key, 0);
}

int key_equal_itself(struct sshkey *key) {
    return ssh_ml_dsa_equal(key, key) != 1;
}

int key_not_equal_another(struct sshkey *key, struct sshkey *other) {
    return ssh_ml_dsa_equal(key, other);
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

int ml_dsa_44_signature_generation(struct sshkey *key) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data);
    char *alg = NULL;

    int r = ssh_ml_dsa_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0);
    
    if (!r) {
        // Signature generated. check if sigtype is inserted correctly starts
        struct sshbuf *b = NULL;
        char *signature_type = NULL;
        if ((b = sshbuf_from(sig, siglen)) == NULL) {
            r = SSH_ERR_ALLOC_FAIL;
            goto out;
        }

        if (sshbuf_get_cstring(b, &signature_type, NULL) != 0) {
            printf("ml-dsa: Failed getting signature type from buffer\n");
            r = SSH_ERR_INVALID_FORMAT;
            goto out;
        }

        if ((r = strcmp("ssh-ml-dsa", signature_type)) != 0) {
            // Should never happen
            printf("ml-dsa: signature type incorrect\n");
            goto out;
        }
      
      out:
        sshbuf_free(b);
    }

    return r;
}

int ml_dsa_44_signature_verification(struct sshkey *key) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data);
    char *alg = NULL;

    if (ssh_ml_dsa_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0)) {
        printf("Failed signature generation for ml-dsa-44 when trying to generate for verification\n");
        return 1;
    }
    
    int r = ssh_ml_dsa_verify(key, sig, siglen, data, datalen, alg, 0, NULL);
    if (r != 0) {
        printf("Error code: %d\n", r);
        printf("Error: %s\n", ssh_err(r));
    }

    return r;
}

int ml_dsa_44_signature_verification_should_fail(struct sshkey *key) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data_signed = "Take your MEDS";
    u_char *data_validated = "Don't take your MEDS";
    size_t datalen_signed = strlen(data_signed);
    size_t datalen_validated = strlen(data_validated);
    char *alg = NULL;

    if (ssh_ml_dsa_sign(key, &sig, &siglen, data_signed, datalen_signed, alg, NULL, NULL, 0)) {
        printf("Failed signature generation for ml-dsa-44 when trying to generate for verification\n");
        return 1;
    }
    
    int r = ssh_ml_dsa_verify(key, sig, siglen, data_validated, datalen_validated, alg, 0, NULL);
    if (r != SSH_ERR_SIGNATURE_INVALID) {
        printf("Error code: %d\n", r);
        printf("Error: %s\n", ssh_err(r));
    }

    return r;
}

int ml_dsa_44_signature_validation_using_sshkey_verify(struct sshkey *key) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data);
    char *alg = NULL;
    int r = SSH_ERR_SIGNATURE_INVALID;
    
    if ((r = ssh_ml_dsa_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0)) != 0) {
        printf("Failed signature generation for ml-dsa-44 when trying to generate for verification\n");
        return r;
    }

    if ((r = sshkey_verify(key, sig, siglen, data, datalen, alg, 0, NULL)) != 0) {
        return r;
    }

    return r;
}

int ml_dsa_44_signing_using_sshkey_sign_direct_verify(struct sshkey *key) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data);
    char *alg = NULL;
    int r = SSH_ERR_SIGNATURE_INVALID;
    
    if ((r = sshkey_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0)) != 0) {
        printf("Failed signature generation for ml-dsa-44 when trying to generate for verification\n");
        return r;
    }

    if ((r = ssh_ml_dsa_verify(key, sig, siglen, data, datalen, alg, 0, NULL)) != 0) {
        return r;
    }

    return r;
}

int ml_dsa_44_sshkey_sign_then_sshkey_verify(struct sshkey *key) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data);
    char *alg = NULL;
    int r = SSH_ERR_SIGNATURE_INVALID;
    
    if ((r = sshkey_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0)) != 0) {
        printf("Failed signature generation for ml-dsa-44 when trying to generate for verification\n");
        return r;
    }

    if ((r = sshkey_verify(key, sig, siglen, data, datalen, alg, 0, NULL)) != 0) {
        return r;
    }

    return r;
}


int main(void) {
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    struct sshkey *other = sshkey_new(KEY_ML_DSA);

    if (generate_key(key)) {
        printf("FAILED KEY GENERATION\n");
        goto out;
    }
    
    if (key_equal_itself(key)) {
        printf("key not equal to itself\n");
        goto out;
    }

    if (key_not_equal_another(key, other)) {
        printf("key equal to another\n");
        goto out;
    }
    
    if (serialize_deserialize_pub_eq(key)) {
        printf("Serialization then deserialization public key is not equal\n");
        goto out;
    }
    
    if (serialize_deserialize_priv_eq(key)) {
        printf("Serialization then deserialization private key is not equal\n");
        goto out;
    }
    
    if (ml_dsa_44_signature_generation(key)) {
        printf("Signature generation fails for ML-DSA-44\n");
        goto out;
    }
    
    if (ml_dsa_44_signature_verification(key)) {
        printf("Signature verification fails for ML-DSA-44\n");
        goto out;
    }
    
    if (ml_dsa_44_signature_verification_should_fail(key) == 0) {
        printf("Signature verification succeeds when it should not for ML-DSA-44\n");
        goto out;
    }

    if (ml_dsa_44_signature_validation_using_sshkey_verify(key)) {
        printf("Signature not verified with sshkey_verify function\n");
        goto out;
    }
    
    if (ml_dsa_44_signing_using_sshkey_sign_direct_verify(key)) {
        printf("Signature not verified when signing with sshkey_sign function\n");
        goto out;
    }
    
    if (ml_dsa_44_sshkey_sign_then_sshkey_verify(key)) {
        printf("Signature not verified using sshkey_sign and sshkey_verify\n");
        goto out;
    }

    printf("All Tests Passed!\n");

  out:
    sshkey_free(key);
    sshkey_free(other);
}