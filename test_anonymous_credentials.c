//
// Created by Alexandros Hasikos on 29/07/2021.
//

#include <core.h>
#include <bls_BN254.h>
#include <string.h>
#include <scheme_D/schemeD_signatures.h>

int test_anonymous_credentials(csprng *prng) {
    const uint32_t number_of_messages = 32;
    int res = 1;

    BIG_256_56 message[number_of_messages];
    for(int i = 0; i < number_of_messages; i++) {
        BIG_256_56_random(message[i], prng);
    }

    schemeD_secret_key sk;
    BIG_256_56 *z_big_buf = malloc(sizeof(BIG_256_56) * number_of_messages);
    schemeD_init_secret_key(&sk, z_big_buf, number_of_messages);
    schemeD_generate_sk(&sk, prng);

    schemeD_public_key pk;
    ECP2_BN254 *Z_ECP_buf = malloc(sizeof(ECP2_BN254) * number_of_messages);
    schemeD_init_public_key(&pk, Z_ECP_buf, NULL, number_of_messages);
    schemeD_generate_pk(&pk, &sk);

    schemeD_signature sig;
    ECP_BN254 *A_ECP_buf = malloc(sizeof(ECP_BN254) * number_of_messages);
    ECP_BN254 *B_ECP_buf = malloc(sizeof(ECP_BN254) * number_of_messages);
    schemeD_init_signature(&sig, A_ECP_buf, B_ECP_buf, number_of_messages);

    schemeD_sign(&sig, message, &sk, prng);

    if(! schemeD_verify(&sig, message, &pk)) res = 0;

    //

    free(z_big_buf);
    free(Z_ECP_buf);
}

int main(){

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

    return 0;
}

