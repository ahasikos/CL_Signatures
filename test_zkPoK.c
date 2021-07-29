//
// Created by Alexandros Hasikos on 21/07/2021.
//

#include <signature_on_committed_value/commitment_scheme.h>
#include <bls_BN254.h>
#include <scheme_D/schemeD_signatures.h>
#include <scheme_C/schemeC_signatures.h>
#include <signature_on_committed_value/sign_commitment.h>


//void test_zkPoK_1(csprng *prng) {
//    const uint32_t number_of_messages = 32;
//    int res;
//
//    BIG_256_56 message[number_of_messages], t[number_of_messages], s[number_of_messages], c;
//
//    BIG_256_56_random(c, prng);
//
//    for(int i = 0; i < number_of_messages; i++) {
//        BIG_256_56_random(message[i], prng);
//    }
//
//    schemeC_secret_key sk;
//    BIG_256_56 *z_big_buf = malloc(sizeof(BIG_256_56) * number_of_messages);
//    schemeC_init_secret_key(&sk, z_big_buf, number_of_messages);
//    schemeC_generate_sk(&sk, prng);
//
//    schemeC_public_key pk;
//    ECP2_BN254 *Z_ECP_buf = malloc(sizeof(ECP2_BN254) * number_of_messages);
//    schemeC_init_public_key(&pk, Z_ECP_buf, number_of_messages);
//    schemeC_generate_pk(&pk, &sk);
//
//    ECP2_BN254 commitment, T;
//
//    //Generate commitment
//    generate_commitment(&commitment, message, &pk);
//
//    prover_1(&T, t, &pk, prng);
//
//    prover_2(s, c, t, message, &pk);
//
//    res = verifier(&T, &commitment, s, c, &pk);
//
//    if(res) {
//        printf("Success\n");
//    } else {
//        printf("Failure\n");
//    }
//
//    free(z_big_buf);
//    free(Z_ECP_buf);
//}

void test_zkPoK_2(csprng *prng) {
    const uint32_t number_of_messages = 32;
    int res = 0;

    BIG_256_56 message[number_of_messages], t[number_of_messages], s[number_of_messages], c;

    BIG_256_56_random(c, prng);

    for(int i = 0; i < number_of_messages; i++) {
        BIG_256_56_random(message[i], prng);
    }

    //User key pair
    schemeD_secret_key user_sk;
    BIG_256_56 *user_z_big_buf = malloc(sizeof(BIG_256_56) * number_of_messages);
    schemeD_init_secret_key(&user_sk, user_z_big_buf, number_of_messages);
    schemeD_generate_sk(&user_sk, prng);

    schemeD_public_key user_pk;
    ECP2_BN254 *user_Z_ECP_buf = malloc(sizeof(ECP2_BN254) * number_of_messages);
    ECP2_BN254 *user_W_ECP_buf = malloc(sizeof(ECP2_BN254) * number_of_messages);
    schemeD_init_public_key(&user_pk, user_Z_ECP_buf, user_W_ECP_buf, number_of_messages);
    schemeD_generate_pk(&user_pk, &user_sk);

    //Signer key pair
    schemeD_secret_key signer_sk;
    BIG_256_56 *signer_z_big_buf = malloc(sizeof(BIG_256_56) * number_of_messages);
    schemeD_init_secret_key(&signer_sk, signer_z_big_buf, number_of_messages);
    schemeD_generate_sk(&signer_sk, prng);

    schemeD_public_key signer_pk;
    ECP2_BN254 *signer_Z_ECP_buf = malloc(sizeof(ECP2_BN254) * number_of_messages);
    ECP2_BN254 *signer_W_ECP_buf = malloc(sizeof(ECP2_BN254) * number_of_messages);
    schemeD_init_public_key(&signer_pk, signer_Z_ECP_buf, signer_W_ECP_buf, number_of_messages);
    schemeD_generate_pk(&signer_pk, &signer_sk);


    //Obtain signature on commited value

    ECP2_BN254 commitment, T;

    generate_commitment(&commitment, message, &user_pk);

    //Prover -> Compute T
    prover_1(&T, t, &user_pk, prng);

    //Verifier -> Send challenge c to prover
    prover_2(s, c, t, message, number_of_messages);

    //Prover -> Send s to verifier
    verifier(&T, &commitment, s, c, &user_pk) ? res++ : (res = 0);

    //Get signature on commited value given the PoK of message succeeded

    schemeD_signature sig;
    ECP_BN254 *A_ECP_buf = malloc(sizeof(ECP_BN254) * number_of_messages);
    ECP_BN254 *B_ECP_buf = malloc(sizeof(ECP_BN254) * number_of_messages);
    schemeD_init_signature(&sig, A_ECP_buf, B_ECP_buf, number_of_messages);

    sign_commitment(&sig, NULL, &signer_sk, prng);




    free(signer_z_big_buf);
    free(signer_Z_ECP_buf);
    free(signer_W_ECP_buf);
    free(user_z_big_buf);
    free(user_Z_ECP_buf);
    free(user_W_ECP_buf);
    free(A_ECP_buf);
    free(B_ECP_buf);

    res ? (printf("Success\n")) : (printf("Failure\n"));
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

//    printf("Testing signature_on_committed_value...");
//    test_zkPoK_1(&prng);

    printf("Testing signature_on_committed_value_2...");
    test_zkPoK_2(&prng);

    return 0;
}
