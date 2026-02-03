#include <stdio.h>
#include <stdint.h>
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "ssh-ml-kem-auth.h"

int generate_key_default() {
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    int r = ssh_ml_kem_auth_generate(key, 0);
    sshkey_free(key);
    return r;
}

int generate_key_incorrect_bit() {
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    int r = ssh_ml_kem_auth_generate(key, 1234567890);
    sshkey_free(key);
    return r != SSH_ERR_INVALID_ARGUMENT;
}

int generate_key_with_bits(int bits) {
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = ssh_ml_kem_auth_generate(key, bits)) != 0) {
        fprintf(stderr, "Failed creating key for ML-KEM-%d\n", bits);
        goto out;
    }

    if ((r = ssh_ml_kem_auth_size(key)) <= 0) {
        // -1 -> information not available
        // 0 -> not considered quantum safe
        fprintf(stderr, "Size of key not possible to get: %d\n", r);
        goto out;
    }

    // valid categories:
    //     ML-KEM-512: 1
    //     ML-KEM-768: 3
    //     ML-KEM-1024: 5
    // Negated to get 0 on success
    switch (bits) {
        case ML_KEM_AUTH_512_BITS:
            /* code */
            r = !(r == 1);
            break;
        
        case ML_KEM_AUTH_768_BITS:
            /* code */
            r = !(r == 3);
            break;
        
        case ML_KEM_AUTH_1024_BITS:
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
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = ssh_ml_kem_auth_generate(key, bits)) != 0) {
        fprintf(stderr, "Failed generating key: %d\n", r);
        goto out;
    }
    r = ssh_ml_kem_auth_equal(key, key) != 1;

  out:
    sshkey_free(key);
    return r;
}

int key_not_equal_another_same_bits(int bits) {
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    struct sshkey *other = sshkey_new(KEY_ML_KEM_AUTH);
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = ssh_ml_kem_auth_generate(key, bits)) != 0) {
        fprintf(stderr, "Failed generating first key: %d\n", r);
        goto out;
    }
    
    if ((r = ssh_ml_kem_auth_generate(other, bits)) != 0) {
        fprintf(stderr, "Failed generating second key: %d\n", r);
        goto out;
    }

    r = ssh_ml_kem_auth_equal(key, other);
  
  out:
    sshkey_free(key);
    sshkey_free(other);
    return r;
}

int key_not_equal_another_different_bits(int key_bits, int other_bits) {
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    struct sshkey *other = sshkey_new(KEY_ML_KEM_AUTH);
    int r = SSH_ERR_INTERNAL_ERROR;
    if ((r = ssh_ml_kem_auth_generate(key, key_bits)) != 0) {
        goto out;
    }
    
    if ((r = ssh_ml_kem_auth_generate(other, other_bits)) != 0) {
        goto out;
    }
    r = ssh_ml_kem_auth_equal(key, other);
  
  out:
    sshkey_free(key);
    sshkey_free(other);
    return r;
}

int copy_public_equal_to_itself(int bits) {
    struct sshkey *from = sshkey_new(KEY_ML_KEM_AUTH);
    struct sshkey *to = sshkey_new(KEY_ML_KEM_AUTH);
    int r = SSH_ERR_INTERNAL_ERROR;

    if ((r = ssh_ml_kem_auth_generate(from, bits)) != 0) {
        fprintf(stderr, "Failed generating key: %d\n", r);
        goto out;
    }

    if ((r = ssh_ml_kem_auth_copy_public(from, to)) != 0) {
        fprintf(stderr, "Failed to copy public key: %d\n", r);
        goto out;
    }

    r = ssh_ml_kem_auth_equal(from, to) != 1;

  out:
    sshkey_free(from);
    sshkey_free(to);
    return r;
}

int serialize_deserialize_pub_eq(int bits) {
    int r = SSH_ERR_INTERNAL_ERROR;
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    struct sshbuf *serialization_buffer = sshbuf_new();
    struct sshkey *deserialized = sshkey_new(KEY_ML_KEM_AUTH);

    if ((r = ssh_ml_kem_auth_generate(key, bits)) != 0) {
        goto out;
    }
    
    if ((r = ssh_ml_kem_auth_serialize_public(key, serialization_buffer, SSHKEY_SERIALIZE_DEFAULT)) != 0) {
        fprintf(stderr, "serialization failed for public key\n");
        goto out;
    }

    if ((r = ssh_ml_kem_auth_deserialize_public("ml-kem", serialization_buffer, deserialized)) != 0) {
        fprintf(stderr, "deserialization failed for public key\n");
        goto out;
    }

    r = ssh_ml_kem_auth_equal(key, deserialized) != 1;

  out:
    sshbuf_free(serialization_buffer);
    sshkey_free(deserialized);
    sshkey_free(key);
    return r;
}

int serialize_deserialize_priv_eq(int bits) {
    int r = SSH_ERR_INTERNAL_ERROR;
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    struct sshbuf *serialization_buffer = sshbuf_new();
    struct sshkey *deserialized = sshkey_new(KEY_ML_KEM_AUTH);
    
    if ((r = ssh_ml_kem_auth_generate(key, bits)) != 0) {
        goto out;
    }

    if ((r = ssh_ml_kem_auth_serialize_private(key, serialization_buffer, SSHKEY_SERIALIZE_DEFAULT)) != 0) {
        fprintf(stderr, "serialization failed for private key\n");
        goto out;
    }
    // printf("buffer length: %d\n", sshbuf_len(serialization_buffer));
    if ((r = ssh_ml_kem_auth_deserialize_private("ml-kem", serialization_buffer, deserialized)) != 0) {
        fprintf(stderr, "deserialization failed for private key: %d\n", r);
        goto out;
    }

    r = ssh_ml_kem_auth_equal(key, deserialized) != 1;

  out:
    sshbuf_free(serialization_buffer);
    sshkey_free(deserialized);
    sshkey_free(key);
    return r;
}

int generate_encapsulation(int bits) {
    int r = SSH_ERR_INTERNAL_ERROR;
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    u_char *ct = NULL;
    size_t ct_len = 0;
    u_char *ss = malloc(ML_KEM_AUTH_SS_LENGTH);

    if ((r = ssh_ml_kem_auth_generate(key, bits)) != 0) {
        fprintf(stderr, "Failed generating key for encapsulation\n");
        goto out;
    }

    if ((r = ssh_ml_kem_auth_encapsulate(key, &ct, &ct_len, ss, ML_KEM_AUTH_SS_LENGTH, NULL, NULL, NULL, 0)) != 0) {
        fprintf(stderr, "Failed encapsulating shared secret\n");
        goto out;
    }

    if (ct == NULL) {
        fprintf(stderr, "Ciphertext is not set after encapsulation\n");
        r = SSH_ERR_KEM_AUTH_CT_NOT_GENERATED;
        goto out;
    }

  out:
    if (ct != NULL) {
        free(ct);
    }
    free(ss);
    sshkey_free(key);
    return r;
}

int encapsulate_decapsulate_ss_eq(int bits) {
    int r = SSH_ERR_INTERNAL_ERROR;
    struct sshkey *key = sshkey_new(KEY_ML_KEM_AUTH);
    char *ct = NULL;
    size_t ct_len = 0;
    char *ss = malloc(ML_KEM_AUTH_SS_LENGTH);
    char *ss_decaps = malloc(ML_KEM_AUTH_SS_LENGTH);

    if ((r = ssh_ml_kem_auth_generate(key, bits)) != 0) {
        fprintf(stderr, "Failed generating key for encapsulation\n");
        goto out;
    }

    if ((r = ssh_ml_kem_auth_encapsulate(key, &ct, &ct_len, ss, ML_KEM_AUTH_SS_LENGTH, NULL, NULL, NULL, 0)) != 0) {
        fprintf(stderr, "Failed encapsulating shared secret\n");
        goto out;
    }

    if (ss == NULL) {
        r = SSH_ERR_KEM_AUTH_SS_NOT_GENERATED;
        fprintf(stderr, "Shared secret is not set after encapsulation\n");
        goto out;
    }

    if (ct == NULL) {
        fprintf(stderr, "Ciphertext is not set after encapsulation\n");
        r = SSH_ERR_KEM_AUTH_CT_NOT_GENERATED;
        goto out;
    }

    if ((r = ssh_ml_kem_auth_decapsulate(key, ct, ct_len, ss_decaps, ML_KEM_AUTH_SS_LENGTH, NULL, 0, NULL)) != 0) {
        fprintf(stderr, "Failed decapsulating ciphertext\n");
        goto out;
    }

    int i = 0; 
    while (i < ML_KEM_AUTH_SS_LENGTH && ss[i] == ss_decaps[i]) {
        i++;
    }

    r = i < ML_KEM_AUTH_SS_LENGTH ? SSH_ERR_KEM_AUTH_SS_MISMATCH : 0;
    if (r != 0) {
        fprintf(stderr, "Mismatch between shared secret before and after decapsulation\n");
    }

  out:
    if (ct != NULL) {
        free(ct);
    }
    if (ss != NULL) {
        free(ss);
    }
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

    int bits = ML_KEM_AUTH_512_BITS;
    printf("    ML-KEM-%d: ", bits);
    if (generate_key_with_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_768_BITS;
    printf("    ML-KEM-%d: ", bits);
    if (generate_key_with_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_1024_BITS;
    printf("    ML-KEM-%d: ", bits);
    if (generate_key_with_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    return 0;
}

int run_key_equality_tests() {
    printf("KEY EQUALITY TESTS\n");
    
    int bits = ML_KEM_AUTH_512_BITS;
    printf("    ML-KEM-%d equal to itself: ", bits);
    if (key_equal_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_768_BITS;
    printf("    ML-KEM-%d equal to itself: ", bits);
    if (key_equal_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_1024_BITS;
    printf("    ML-KEM-%d equal to itself: ", bits);
    if (key_equal_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    bits = ML_KEM_AUTH_512_BITS;
    printf("    ML-KEM-%d not equal to another of same type: ", bits);
    if (key_not_equal_another_same_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_768_BITS;
    printf("    ML-KEM-%d not equal to another of same type: ", bits);
    if (key_not_equal_another_same_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_1024_BITS;
    printf("    ML-KEM-%d not equal to another of same type: ", bits);
    if (key_not_equal_another_same_bits(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    printf("    ML-KEM-%d not equal to ML-KEM-%d: ", ML_KEM_AUTH_512_BITS, ML_KEM_AUTH_768_BITS);
    if (key_not_equal_another_different_bits(ML_KEM_AUTH_512_BITS, ML_KEM_AUTH_768_BITS)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");

    printf("    ML-KEM-%d not equal to ML-KEM-%d: ", ML_KEM_AUTH_768_BITS, ML_KEM_AUTH_1024_BITS);
    if (key_not_equal_another_different_bits(ML_KEM_AUTH_768_BITS, ML_KEM_AUTH_1024_BITS)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    return 0;
}

int run_copy_public_tests() {
    printf("COPY PUBLIC TESTS\n");
    int bits = ML_KEM_AUTH_512_BITS;
    printf("    ML-KEM-%d equal to itself when pulic is copied: ", bits);
    if (copy_public_equal_to_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_768_BITS;
    printf("    ML-KEM-%d equal to itself when pulic is copied: ", bits);
    if (copy_public_equal_to_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_1024_BITS;
    printf("    ML-KEM-%d equal to itself when pulic is copied: ", bits);
    if (copy_public_equal_to_itself(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    return 0;
}

int run_key_serialization_tests() {
    printf("KEY (DE)SERIALIZATION TESTS\n");
    
    int bits = ML_KEM_AUTH_512_BITS;
    printf("    ML-KEM-%d public (de)serialization: ", bits);
    if (serialize_deserialize_pub_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_512_BITS;
    printf("    ML-KEM-%d private (de)serialization: ", bits);
    if (serialize_deserialize_priv_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_768_BITS;
    printf("    ML-KEM-%d public (de)serialization: ", bits);
    if (serialize_deserialize_pub_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_768_BITS;
    printf("    ML-KEM-%d private (de)serialization: ", bits);
    if (serialize_deserialize_priv_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_1024_BITS;
    printf("    ML-KEM-%d public (de)serialization: ", bits);
    if (serialize_deserialize_pub_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_1024_BITS;
    printf("    ML-KEM-%d private (de)serialization: ", bits);
    if (serialize_deserialize_priv_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    return 0;
}

int run_encapsulation_tests() {
    printf("KEY ENCAPSULATION TESTS\n");
    
    int bits = ML_KEM_AUTH_512_BITS;
    printf("    ML-KEM-%d encapsulation: ", bits);
    if (generate_encapsulation(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_768_BITS;
    printf("    ML-KEM-%d encapsulation: ", bits);
    if (generate_encapsulation(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_1024_BITS;
    printf("    ML-KEM-%d encapsulation: ", bits);
    if (generate_encapsulation(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    return 0;
}

int run_decapsulation_tests() {
    printf("KEY DECAPSULATION TESTS\n");
    
    int bits = ML_KEM_AUTH_512_BITS;
    printf("    ML-KEM-%d decapsulation: ", bits);
    if (encapsulate_decapsulate_ss_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_768_BITS;
    printf("    ML-KEM-%d decapsulation: ", bits);
    if (encapsulate_decapsulate_ss_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    bits = ML_KEM_AUTH_1024_BITS;
    printf("    ML-KEM-%d decapsulation: ", bits);
    if (encapsulate_decapsulate_ss_eq(bits)) {
        printf("[x]\n");
        return 1;
    }
    printf("[v]\n");
    
    return 0;
}

int run_tests() {
    printf("STARTING ML-KEM-AUTH TESTS\n");
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
    if (run_encapsulation_tests()) {
        return 1;
    }
    
    printf("===================================\n");
    if (run_decapsulation_tests()) {
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