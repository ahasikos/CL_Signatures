//
// Created by Alexandros Hasikos on 09/07/2021.
//

#include "scheme_A/schemeA_signatures.h"
#include "scheme_B/schemeB_signatures.h"

#include <core.h>
#include <bls_BN254.h>

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


    return 0;

}
