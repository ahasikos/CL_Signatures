//
// Created by Alexandros Hasikos on 21/07/2021.
//

#include <commitment_schemes/PoK_message/PoK_message.h>
#include <bls_BN254.h>
#include <signatures/schemeD/schemeD.h>
#include <sign_commitment/sign_commitment.h>
#include <ecdh_BN254.h>
#include <commitment_schemes/PoK_signature/PoK_signature.h>
#include <utils/utils.h>

void test_zkPoK_2(csprng *prng) {
    const uint32_t number_of_messages = 32;
    int res = 0;

    BIG_256_56 message[number_of_messages], t[number_of_messages], s[number_of_messages], challenge_1;

    BIG_256_56_random(challenge_1, prng);

    for(int i = 0; i < number_of_messages; i++) {
        BIG_256_56_random(message[i], prng);
    }

    //User key pair
    schemeD_sk user_sk;
    schemeD_pk user_pk;

    schemeD_init_keypair(&user_sk, &user_pk, number_of_messages);
    schemeD_generate_sk(&user_sk, prng);
    schemeD_generate_pk(&user_pk, &user_sk);


    //Signer key pair
    schemeD_sk signer_sk;
    schemeD_pk signer_pk;

    schemeD_init_keypair(&signer_sk, &signer_pk, number_of_messages);
    schemeD_generate_sk(&signer_sk, prng);
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

    schemeD_sig sig;
    schemeD_init_signature(&sig, number_of_messages);

    ECP_BN254 converted_commitment;

    commitment_conversion(&converted_commitment, &user_sk, &sig, message);

    ECP_BN254 g_1;
    ECP_BN254_generator(&g_1);
    ECP2_BN254 g_2;
    ECP2_BN254_generator(&g_2);


    sign_commitment(&sig, &converted_commitment, &signer_sk, prng);

    schemeD_sig blind_sig;
    schemeD_init_signature(&blind_sig, number_of_messages);


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

    schemeD_destroy_keypair(&user_sk, &user_pk);
    schemeD_destroy_keypair(&signer_sk, &signer_pk);
    schemeD_destroy_signature(&sig);
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

//    printf("Testing sign_commitment...");
//    test_zkPoK_1(&prng);

    printf("Testing signature_on_committed_value_2...");
    test_zkPoK_2(&prng);

    return 0;
}
