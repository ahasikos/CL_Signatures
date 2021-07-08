#include <stdio.h>
#include <core.h>
#include <bls_BN254.h>
#include <fp_BN254.h>
#include "scheme_A/schemeA_signatures.h"


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

    schemeA_secret_key sk;
    schemeA_public_key pk;

    schemeA_init_sk(&sk);

    schemeA_generate_sk(&sk, &prng);

    schemeA_generate_pk(&pk, &sk);

    BIG_256_56 message;
    BIG_256_56_random(message, &prng);

    schemeA_signature sig;

    schemeA_sign(&sig, message, &sk, &prng);

    if(schemeA_verify(&sig, message, &pk)) {
        printf("Success");
    } else {
        printf("Failure");
    }
    return 0;
}
