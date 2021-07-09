//
// Created by Alexandros Hasikos on 09/07/2021.
//

#include <core.h>
#include <bls_BN254.h>

#include "scheme_C/schemeC_signatures.h"
#include "scheme_A/schemeA_signatures.h"
#include "scheme_B/schemeB_signatures.h"

void test_scheme_A(csprng *prng) {
    schemeA_secret_key sk;
    schemeA_public_key pk;
    schemeA_signature sig;

    schemeA_generate_sk(&sk, prng);

    schemeA_generate_pk(&pk, &sk);

    BIG_256_56 message;
    BIG_256_56_random(message, prng);

    schemeA_sign(&sig, message, &sk, prng);

    if(schemeA_verify(&sig, message, &pk)) {
        printf("Success\n");
    } else {
        printf("Failure\n");
    }
}

void test_scheme_B(csprng *prng) {
    schemeB_secret_key sk;
    schemeB_public_key pk;
    schemeB_signature sig;

    schemeB_generate_sk(&sk, prng);

    schemeB_generate_pk(&pk, &sk);

    BIG_256_56 message, randomness;

    BIG_256_56_random(message, prng);
    BIG_256_56_random(randomness, prng);

    schemeB_sign(&sig, message, randomness, &sk, prng);

    if(schemeB_verify(&sig, message, randomness, &pk)) {
        printf("Success\n");
    } else {
        printf("Failure\n");
    }
}

void test_scheme_C(csprng *prng) {
    const uint32_t number_of_messages = 32;

    BIG_256_56 message[number_of_messages];
    for(int i = 0; i < number_of_messages; i++) {
        BIG_256_56_random(message[i], prng);
    }

    schemeC_secret_key sk;
    BIG_256_56 *z_big_buf = malloc(sizeof(BIG_256_56) * number_of_messages);
    schemeC_init_secret_key(&sk, z_big_buf, number_of_messages);
    schemeC_generate_sk(&sk, prng);

    schemeC_public_key pk;
    ECP2_BN254 *Z_ECP_buf = malloc(sizeof(ECP2_BN254) * number_of_messages);
    schemeC_init_public_key(&pk, Z_ECP_buf, number_of_messages);
    schemeC_generate_pk(&pk, &sk);

    schemeC_signature sig;
    ECP_BN254 *A_ECP_buf = malloc(sizeof(ECP_BN254) * number_of_messages);
    ECP_BN254 *B_ECP_buf = malloc(sizeof(ECP_BN254) * number_of_messages);
    schemeC_init_signature(&sig, A_ECP_buf, B_ECP_buf, number_of_messages);

    schemeC_sign(&sig, message, &sk, prng);

    free(z_big_buf);
    free(Z_ECP_buf);
}

int main() {

    //---------------------------------------------------
    // Init
    //---------------------------------------------------
    if(BLS_BN254_INIT() != BLS_OK) {
        printf("Error\n");
        exit(1);
    }
    //---------------------------------------------------


    //---------------------------------------------------
    // Declare and seed prng
    //---------------------------------------------------
    char seed[20] = {0};
    csprng prng;

    RAND_seed(&prng, sizeof(seed), seed);
    //---------------------------------------------------

    printf("Testing Scheme A...");
    test_scheme_A(&prng);

    printf("Testing Scheme B...");
    test_scheme_B(&prng);

    printf("Testing Scheme C...");
    test_scheme_C(&prng);


    return 0;

}