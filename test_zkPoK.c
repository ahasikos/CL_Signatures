//
// Created by Alexandros Hasikos on 21/07/2021.
//

#include <signature_on_committed_value/commitment_scheme.h>
#include <bls_BN254.h>


void test_zkPoK(csprng *prng) {
    const uint32_t number_of_messages = 32;
    int res;

    BIG_256_56 message[number_of_messages], t[number_of_messages], s[number_of_messages], c;

    BIG_256_56_random(c, prng);

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

    ECP2_BN254 commitment, T;

    //Generate commitment
    generate_commitment(&commitment, message, &pk);

    prover_1(&T, t, &pk, prng);

    prover_2(s, c, t, message, &pk);

    res = verifier(&T, &commitment, s, c, &pk);

    if(res) {
        printf("Success\n");
    } else {
        printf("Failure\n");
    }

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

    printf("Testing signature_on_committed_value...");
    test_zkPoK(&prng);

    return 0;
}
