//
// Created by Alexandros Hasikos on 21/07/2021.
//

#include <commitment_schemes/PoK_message/PoK_message.h>
#include <bls_BN254.h>
#include <signatures/schemeD/schemeD.h>
#include <signature_on_committed_value/sign_commitment.h>
#include <ecdh_BN254.h>
#include <signature_on_committed_value/signature_PoK.h>
#include <utils/utils.h>


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
//    res = PoK_verifier(&T, &commitment, s, c, &pk);
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

    BIG_256_56 message[number_of_messages], t[number_of_messages], s[number_of_messages], challenge_1;

    BIG_256_56_random(challenge_1, prng);

    for(int i = 0; i < number_of_messages; i++) {
        BIG_256_56_random(message[i], prng);
    }

    //User key pair
    schemeD_secret_key user_sk;
    BIG_256_56 user_z_big_buf[number_of_messages];
    schemeD_init_secret_key(&user_sk, user_z_big_buf, number_of_messages);
    schemeD_generate_sk(&user_sk, prng);

    schemeD_public_key user_pk;
    ECP2_BN254 user_Z_ECP_buf[number_of_messages];
    ECP2_BN254 user_W_ECP_buf[number_of_messages];
    schemeD_init_public_key(&user_pk, user_Z_ECP_buf, user_W_ECP_buf, number_of_messages);
    schemeD_generate_pk(&user_pk, &user_sk);

    //Signer key pair
    schemeD_secret_key signer_sk;
    BIG_256_56 signer_z_big_buf[number_of_messages];
    schemeD_init_secret_key(&signer_sk, signer_z_big_buf, number_of_messages);
    schemeD_generate_sk(&signer_sk, prng);

    schemeD_public_key signer_pk;
    ECP2_BN254 signer_Z_ECP_buf[number_of_messages];
    ECP2_BN254 signer_W_ECP_buf[number_of_messages];
    schemeD_init_public_key(&signer_pk, signer_Z_ECP_buf, signer_W_ECP_buf, number_of_messages);
    schemeD_generate_pk(&signer_pk, &signer_sk);


    //Obtain signature on commited value

    ECP2_BN254 T;

    ECP2_BN254 commitment_1;

    generate_commitment(&commitment_1, message, &user_pk);

    //Prover -> Compute T
    prover_1(&T, t, &user_pk, prng);

    //Verifier -> Send challenge_2 challenge_1 to prover
    prover_2(s, challenge_1, t, message, number_of_messages);

    //Prover -> Send s to PoK_verifier
    verifier(&T, &commitment_1, s, challenge_1, &user_pk) ? res++ : (res = 0);

    //Get signature on commited value given the PoK of message succeeded

    schemeD_signature sig;
    ECP_BN254 A_ECP_buf[number_of_messages];
    ECP_BN254 B_ECP_buf[number_of_messages];
    schemeD_init_signature(&sig, A_ECP_buf, B_ECP_buf, number_of_messages);

    ECP_BN254 converted_commitment;

    commitment_conversion(&converted_commitment, &user_sk, &sig, message);

    ECP_BN254 g_1;
    ECP_BN254_generator(&g_1);
    ECP2_BN254 g_2;
    ECP2_BN254_generator(&g_2);

    int q = pairing_and_equality_check(&commitment_1, &g_1, &g_2, &converted_commitment);

    sign_commitment(&sig, &converted_commitment, &signer_sk, prng);

    schemeD_signature blind_sig;
    ECP_BN254 blind_sig_A_ECP_buf[number_of_messages];
    ECP_BN254 blind_sig_B_ECP_buf[number_of_messages];
    schemeD_init_signature(&blind_sig, blind_sig_A_ECP_buf, blind_sig_B_ECP_buf, number_of_messages);


    PoK_proof proof;
    BIG_256_56_random(proof.r, prng);

    PoK_compute_blind_signature(&blind_sig, &sig, &proof, prng);

    FP12_BN254 commitment_2;

    PoK_generate_commitment(&commitment_2, &proof, message, &signer_pk, &blind_sig);

    FP12_BN254 T_2;
    BIG_256_56 t1;
    BIG_256_56 t2[number_of_messages];

    PoK_prover_1(&T_2, t1, t2, &signer_pk, &blind_sig, prng);

    BIG_256_56 s1, challenge_2;
    BIG_256_56 s2[number_of_messages];

    BIG_256_56_random(challenge_2, prng);

    PoK_prover_2(s1, s2, challenge_2, t1, t2, message, &proof, &blind_sig);

    PoK_verifier(s1, s2, challenge_2, &T_2, &commitment_2, &signer_pk, &blind_sig) ? res++ : (res = 0);

    res == 2 ? (printf("Success\n")) : (printf("Failure\n"));
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
