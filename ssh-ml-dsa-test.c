#include <stdio.h>
#include <stdint.h>
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "ssh-ml-dsa.h"

#define ML_DSA_44_BITS 44
#define ML_DSA_65_BITS 65
#define ML_DSA_87_BITS 87

int generate_key_default() {
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    int r = ssh_ml_dsa_generate(key, 0);
    sshkey_free(key);
    return r;
}

int generate_key_incorrect_bit() {
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    int r = ssh_ml_dsa_generate(key, 1234567890);
    sshkey_free(key);
    return r != SSH_ERR_INVALID_ARGUMENT;
}

int generate_key_with_bits(int bits) {
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        fprintf(stderr, "Failed creating key for ML-DSA-%d\n", bits);
        goto out;
    }

    if ((r = ssh_ml_dsa_size(key)) <= 0) {
        // -1 -> information not available
        // 0 -> not considered quantum safe
        fprintf(stderr, "Size of key not possible to get: %d\n", r);
        goto out;
    }

    // valid categories:
    //     ML-DSA-44: 2
    //     ML-DSA-65: 3
    //     ML-DSA-87: 5
    // Negated to get 0 on success
    switch (bits) {
        case ML_DSA_44_BITS:
            /* code */
            r = !(r == 2);
            break;
        
        case ML_DSA_65_BITS:
            /* code */
            r = !(r == 3);
            break;
        
        case ML_DSA_87_BITS:
            /* code */
            r = !(r == 5);
            break;
        
        default:
            r = SSH_ERR_INTERNAL_ERROR;
            fprintf(stderr, "bits parameter is incorrect\n");
            break;
    }

  out:
    sshkey_free(key);
    return r;
}

int key_equal_itself(int bits) {
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        fprintf(stderr, "Failed generating key: %d\n", r);
        goto out;
    }
    r = ssh_ml_dsa_equal(key, key) != 1;

  out:
    sshkey_free(key);
    return r;
}

int key_not_equal_another_same_bits(int bits) {
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    struct sshkey *other = sshkey_new(KEY_ML_DSA);
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        fprintf(stderr, "Failed generating first key: %d\n", r);
        goto out;
    }
    
    if ((r = ssh_ml_dsa_generate(other, bits)) != 0) {
        fprintf(stderr, "Failed generating second key: %d\n", r);
        goto out;
    }

    r = ssh_ml_dsa_equal(key, other);
  
  out:
    sshkey_free(key);
    sshkey_free(other);
    return r;
}

int key_not_equal_another_different_bits(int key_bits, int other_bits) {
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    struct sshkey *other = sshkey_new(KEY_ML_DSA);
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = ssh_ml_dsa_generate(key, key_bits)) != 0) {
        goto out;
    }
    
    if ((r = ssh_ml_dsa_generate(other, other_bits)) != 0) {
        goto out;
    }
    r = ssh_ml_dsa_equal(key, other);
  
  out:
    sshkey_free(key);
    sshkey_free(other);
    return r;
}

int copy_public_equal_to_itself(int bits) {
    struct sshkey *from = sshkey_new(KEY_ML_DSA);
    struct sshkey *to = sshkey_new(KEY_ML_DSA);
    int r = SSH_ERR_INTERNAL_ERROR;

    if ((r = ssh_ml_dsa_generate(from, bits)) != 0) {
        fprintf(stderr, "Failed generating key: %d\n", r);
        goto out;
    }

    if ((r = ssh_ml_dsa_copy_public(from, to)) != 0) {
        fprintf(stderr, "Failed to copy public key: %d\n", r);
        goto out;
    }

    r = ssh_ml_dsa_equal(from, to) != 1;

  out:
    sshkey_free(from);
    sshkey_free(to);
    return r;
}

int serialize_deserialize_pub_eq(int bits) {
    int r = SSH_ERR_INTERNAL_ERROR;
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    struct sshbuf *serialization_buffer = sshbuf_new();
    struct sshkey *deserialized = sshkey_new(KEY_ML_DSA);

    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        goto out;
    }
    
    if ((r = ssh_ml_dsa_serialize_public(key, serialization_buffer, SSHKEY_SERIALIZE_DEFAULT)) != 0) {
        fprintf(stderr, "serialization failed for public key\n");
        goto out;
    }

    if ((r = ssh_ml_dsa_deserialize_public("ml-dsa", serialization_buffer, deserialized)) != 0) {
        fprintf(stderr, "deserialization failed for public key\n");
        goto out;
    }

    r = ssh_ml_dsa_equal(key, deserialized) != 1;

  out:
    sshbuf_free(serialization_buffer);
    sshkey_free(deserialized);
    sshkey_free(key);
    return r;
}

int serialize_deserialize_priv_eq(int bits) {
    int r = SSH_ERR_INTERNAL_ERROR;
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    struct sshbuf *serialization_buffer = sshbuf_new();
    struct sshkey *deserialized = sshkey_new(KEY_ML_DSA);
    
    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        goto out;
    }

    if ((r = ssh_ml_dsa_serialize_private(key, serialization_buffer, SSHKEY_SERIALIZE_DEFAULT)) != 0) {
        fprintf(stderr, "serialization failed for private key\n");
        goto out;
    }
    // printf("buffer length: %d\n", sshbuf_len(serialization_buffer));
    if ((r = ssh_ml_dsa_deserialize_private("ml-dsa", serialization_buffer, deserialized)) != 0) {
        fprintf(stderr, "deserialization failed for private key: %d\n", r);
        goto out;
    }

    r = ssh_ml_dsa_equal(key, deserialized) != 1;

  out:
    sshbuf_free(serialization_buffer);
    sshkey_free(deserialized);
    sshkey_free(key);
    return r;
}

int ml_dsa_signature_generation(int bits) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data);
    char *alg = NULL;
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    int r = SSH_ERR_INTERNAL_ERROR;

    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        goto out;
    }
    
    if ((r = ssh_ml_dsa_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0)) == 0) {
        // Signature generated. check if sigtype is inserted correctly at the start
        struct sshbuf *b = NULL;
        char *signature_type = NULL;
        char *expected_signature_type = "ssh-ml-dsa";
        if ((b = sshbuf_from(sig, siglen)) == NULL) {
            r = SSH_ERR_ALLOC_FAIL;
            goto out_sig_generated;
        }

        if (sshbuf_get_cstring(b, &signature_type, NULL) != 0) {
            fprintf(stderr, "ml-dsa: Failed getting signature type from buffer\n");
            r = SSH_ERR_INVALID_FORMAT;
            goto out_sig_generated;
        }

        if (strcmp(expected_signature_type, signature_type) != 0) {
            fprintf(stderr, "Signature type is not what was expected\n");
            r = SSH_ERR_INVALID_FORMAT;
            goto out_sig_generated;
        }
      
      out_sig_generated:
        sshbuf_free(b);
    }

  out:
    sshkey_free(key);
    return r;
}

int ml_dsa_signature_verification(int bits) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data) + 1;
    char *alg = NULL;
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    int r = SSH_ERR_INTERNAL_ERROR;

    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        goto out;
    }

    if ((r = ssh_ml_dsa_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0)) != 0) {
        fprintf(stderr, "Failed signature generation for ml-dsa-%d when trying to generate for verification\n", bits);
        goto out;
    }

    fprintf(stderr, "ML-DSA-%d sig_len: %d\n", bits, siglen);
    
    if ((r = ssh_ml_dsa_verify(key, sig, siglen, data, datalen, alg, 0, NULL)) != 0) {
        fprintf(stderr, "Error code: %d\n", r);
        fprintf(stderr, "Error: %s\n", ssh_err(r));
    }

  out:
    sshkey_free(key);
    return r;
}

int ml_dsa_signature_verification_different_data(int bits) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data_signed = "Take your MEDS";
    u_char *data_validated = "Don't take your MEDS";
    size_t datalen_signed = strlen(data_signed);
    size_t datalen_validated = strlen(data_validated);
    char *alg = NULL;
    struct sshkey *key = sshkey_new(KEY_ML_DSA);
    int r = SSH_ERR_INTERNAL_ERROR;

    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        goto out;
    }

    if ((r = ssh_ml_dsa_sign(key, &sig, &siglen, data_signed, datalen_signed, alg, NULL, NULL, 0)) != 0) {
        fprintf(stderr, "Failed signature generation for ml-dsa-%d when trying to generate for verification\n", bits);
        goto out;
    }
    
    if ((r = ssh_ml_dsa_verify(key, sig, siglen, data_validated, datalen_validated, alg, 0, NULL)) != SSH_ERR_SIGNATURE_INVALID) {
        fprintf(stderr, "Error code: %d\n", r);
        fprintf(stderr, "Error: %s\n", ssh_err(r));
    }

  out:
    sshkey_free(key);
    return r;
}

int ml_dsa_signing_using_sshkey_sign_direct_verify(int bits) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data);
    char *alg = NULL;
    int r = SSH_ERR_SIGNATURE_INVALID;
    struct sshkey *key = sshkey_new(KEY_ML_DSA);

    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        goto out;
    }
    
    if ((r = sshkey_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0)) != 0) {
        fprintf(stderr, "Failed signature generation for ml-dsa-44 when trying to generate for verification\n");
        goto out;
    }

    if ((r = ssh_ml_dsa_verify(key, sig, siglen, data, datalen, alg, 0, NULL)) != 0) {
        goto out;
    }

  out:
    sshkey_free(key);
    return r;
}

int ml_dsa_signature_validation_using_sshkey_verify(int bits) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data);
    char *alg = NULL;
    int r = SSH_ERR_SIGNATURE_INVALID;
    struct sshkey *key = sshkey_new(KEY_ML_DSA);

    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        goto out;
    }
    
    if ((r = ssh_ml_dsa_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0)) != 0) {
        printf("Failed signature generation for ml-dsa-44 when trying to generate for verification\n");
        goto out;
    }

    if ((r = sshkey_verify(key, sig, siglen, data, datalen, alg, 0, NULL)) != 0) {
        goto out;
    }

  out:
    sshkey_free(key);
    return r;
}


int ml_dsa_sshkey_sign_then_sshkey_verify(int bits) {
    u_char *sig = NULL;
    size_t siglen; // will be overwritten by the signing function
    u_char *data = "Take your MEDS";
    size_t datalen = strlen(data);
    char *alg = NULL;
    int r = SSH_ERR_SIGNATURE_INVALID;
    struct sshkey *key = sshkey_new(KEY_ML_DSA);

    if ((r = ssh_ml_dsa_generate(key, bits)) != 0) {
        goto out;
    }
    
    if ((r = sshkey_sign(key, &sig, &siglen, data, datalen, alg, NULL, NULL, 0)) != 0) {
        printf("Failed signature generation for ml-dsa-44 when trying to generate for verification\n");
        goto out;
    }

    if ((r = sshkey_verify(key, sig, siglen, data, datalen, alg, 0, NULL)) != 0) {
        goto out;
    }

  out:
    sshkey_free(key);
    return r;
}

int run_key_generation_tests() {
    printf("KEY GENERATION TESTS:\n");
    printf("    Default bits: ");
    if (generate_key_default()) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    printf("    Incorrect bits: ");
    if (generate_key_incorrect_bit()) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");

    int bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d: ", bits);
    if (generate_key_with_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d: ", bits);
    if (generate_key_with_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d: ", bits);
    if (generate_key_with_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    return 0;
}

int run_key_equality_tests() {
    printf("KEY EQUALITY TESTS\n");
    
    int bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d equal to itself: ", bits);
    if (key_equal_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d equal to itself: ", bits);
    if (key_equal_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d equal to itself: ", bits);
    if (key_equal_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d not equal to another of same type: ", bits);
    if (key_not_equal_another_same_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d not equal to another of same type: ", bits);
    if (key_not_equal_another_same_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d not equal to another of same type: ", bits);
    if (key_not_equal_another_same_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    printf("    ML-DSA-%d not equal to ML-DSA-%d: ", ML_DSA_44_BITS, ML_DSA_65_BITS);
    if (key_not_equal_another_different_bits(ML_DSA_44_BITS, ML_DSA_65_BITS)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");

    printf("    ML-DSA-%d not equal to ML-DSA-%d: ", ML_DSA_65_BITS, ML_DSA_87_BITS);
    if (key_not_equal_another_different_bits(ML_DSA_65_BITS, ML_DSA_87_BITS)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    return 0;
}

int run_copy_public_tests() {
    printf("COPY PUBLIC TESTS\n");
    int bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d equal to itself when pulic is copied: ", bits);
    if (copy_public_equal_to_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d equal to itself when pulic is copied: ", bits);
    if (copy_public_equal_to_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d equal to itself when pulic is copied: ", bits);
    if (copy_public_equal_to_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    return 0;
}

int run_key_serialization_tests() {
    printf("KEY (DE)SERIALIZATION TESTS\n");
    
    int bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d public (de)serialization: ", bits);
    if (serialize_deserialize_pub_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d private (de)serialization: ", bits);
    if (serialize_deserialize_priv_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d public (de)serialization: ", bits);
    if (serialize_deserialize_pub_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d private (de)serialization: ", bits);
    if (serialize_deserialize_priv_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d public (de)serialization: ", bits);
    if (serialize_deserialize_pub_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d private (de)serialization: ", bits);
    if (serialize_deserialize_priv_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    return 0;
}

int run_signature_generation_tests() {
    printf("KEY SIGNATURE GENERATION TESTS\n");
    
    int bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d: ", bits);
    if (ml_dsa_signature_generation(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d: ", bits);
    if (ml_dsa_signature_generation(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d: ", bits);
    if (ml_dsa_signature_generation(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    return 0;
}

int run_signature_verification_tests() {
    printf("KEY SIGNATURE VERIFICATION TESTS\n");
    
    int bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d direct verification should succeed: ", bits);
    if (ml_dsa_signature_verification(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d direct verification should fail: ", bits);
    if (ml_dsa_signature_verification_different_data(bits) == 0) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");

    bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d verification using direct sign, sshkey_verify: ", bits);
    if (ml_dsa_signature_validation_using_sshkey_verify(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d verification using sshkey_sign, direct verification: ", bits);
    if (ml_dsa_signing_using_sshkey_sign_direct_verify(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_44_BITS;
    printf("    ML-DSA-%d verification using sshkey_sign, sshkey_verify: ", bits);
    if (ml_dsa_sshkey_sign_then_sshkey_verify(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d direct verification should succeed: ", bits);
    if (ml_dsa_signature_verification(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d direct verification should fail: ", bits);
    if (ml_dsa_signature_verification_different_data(bits) == 0) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");

    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d verification using direct sign, sshkey_verify: ", bits);
    if (ml_dsa_signature_validation_using_sshkey_verify(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d verification using sshkey_sign, direct verification: ", bits);
    if (ml_dsa_signing_using_sshkey_sign_direct_verify(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_65_BITS;
    printf("    ML-DSA-%d verification using sshkey_sign, sshkey_verify: ", bits);
    if (ml_dsa_sshkey_sign_then_sshkey_verify(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d direct verification should succeed: ", bits);
    if (ml_dsa_signature_verification(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d direct verification should fail: ", bits);
    if (ml_dsa_signature_verification_different_data(bits) == 0) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");

    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d verification using direct sign, sshkey_verify: ", bits);
    if (ml_dsa_signature_validation_using_sshkey_verify(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d verification using sshkey_sign, direct verification: ", bits);
    if (ml_dsa_signing_using_sshkey_sign_direct_verify(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_DSA_87_BITS;
    printf("    ML-DSA-%d verification using sshkey_sign, sshkey_verify: ", bits);
    if (ml_dsa_sshkey_sign_then_sshkey_verify(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    return 0;
}

int run_tests() {
    printf("STARTING ML-DSA TESTS\n");
    printf("===================================\n");
    if (run_key_generation_tests()) {
        return 1;
    }
    
    printf("===================================\n");
    if (run_key_equality_tests()) {
        return 1;
    }
    
    printf("===================================\n");
    if (run_copy_public_tests()) {
        return 1;
    }
    
    printf("===================================\n");
    if (run_key_serialization_tests()) {
        return 1;
    }
    
    printf("===================================\n");
    if (run_signature_generation_tests()) {
        return 1;
    }
    
    printf("===================================\n");
    if (run_signature_verification_tests()) {
        return 1;
    }


    printf("===================================\n");
    printf("All Tests Passed!\n");
    return 0;
}

int main(void) {
    if (run_tests()) {
        printf("===================================\n");
        printf("A test failed. Check log for details.\n");
        return 1;
    }
    return 0;
}