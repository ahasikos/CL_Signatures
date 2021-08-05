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
#include "assert.h"

#define NUMBER_OF_MESSAGES 32

void create_key_pair(schemeD_sk *sk, schemeD_pk *pk, csprng *prng, uint32_t n) {
    schemeD_init_keypair(sk, pk, n);
    schemeD_generate_sk(sk, prng);
    schemeD_generate_pk(pk, sk);
}

int execute_PoK_of_message_protocol_and_obtain_signature(schemeD_sig *sig, BIG_256_56 *message, schemeD_pk *user_pk,
                                                         schemeD_sk *user_sk, schemeD_sk *signer_sk, csprng *prng) {
    BIG_256_56 challenge, t[NUMBER_OF_MESSAGES], s[NUMBER_OF_MESSAGES];
    ECP2_BN254 T, commitment;

    generate_commitment(&commitment, message, user_pk);

    //Prover(Compute T) -> Verifier
    prover_1(&T, t, user_pk, prng);

    //Compute challenge
    BIG_256_56_random(challenge, prng);

    //Prover(Compute s based on challenge) -> Verifier
    prover_2(s, challenge, t, message, NUMBER_OF_MESSAGES);

    //Verifier(Given T, commitment and s verify PoK) -> 1 or 0
    assert(verifier(&T, &commitment, s, challenge, user_pk));

    ECP_BN254 converted_commitment;

    commitment_conversion(&converted_commitment, user_sk, sig, message);

    sign_commitment(sig, &converted_commitment, signer_sk, prng);

    return 1;
}

void compute_blind_signature(schemeD_sig *blind_sig, schemeD_sig *sig, PoK_randomness *randomness, csprng *prng) {
    PoK_compute_blind_signature(blind_sig, sig, randomness, prng);
}

int execute_PoK_of_signature_and_verify_pairings(schemeD_sig *sig, schemeD_pk *pk, PoK_randomness *randomness,
                                                 BIG_256_56 *message, csprng *prng) {

    FP12_BN254 commitment;

    PoK_generate_commitment(&commitment, randomness, message, pk, sig);

    FP12_BN254 T;
    BIG_256_56 t1, t2[NUMBER_OF_MESSAGES], s1, s2[NUMBER_OF_MESSAGES], challenge;

    //Generate T
    PoK_prover_1(&T, t1, t2, pk, sig, prng);

    //Generate challenge
    BIG_256_56_random(challenge, prng);

    //Generate s1, s1
    PoK_prover_2(s1, s2, challenge, t1, t2, message, randomness, sig);

    //Verify randomness
    assert(PoK_verifier(s1, s2, challenge, &T, &commitment, pk, sig));

    //Verify pairings
    assert(PoK_verify_pairings(sig, pk));

    return 1;
}

void test_anonymous_credentials(csprng *prng) {

    BIG_256_56 message[NUMBER_OF_MESSAGES], t[NUMBER_OF_MESSAGES], s[NUMBER_OF_MESSAGES], challenge_1;

    BIG_256_56_random(challenge_1, prng);

    for(int i = 0; i < NUMBER_OF_MESSAGES; i++) {
        BIG_256_56_random(message[i], prng);
    }

    //User key pair
    schemeD_sk user_sk;
    schemeD_pk user_pk;
    create_key_pair(&user_sk, &user_pk, prng, NUMBER_OF_MESSAGES);


    //Signer key pair
    schemeD_sk signer_sk;
    schemeD_pk signer_pk;
    create_key_pair(&signer_sk, &signer_pk, prng, NUMBER_OF_MESSAGES);

    //Execute PoK of message protocol and obtain signature
    schemeD_sig sig, blind_sig;
    schemeD_init_signature(&sig, NUMBER_OF_MESSAGES);
    schemeD_init_signature(&blind_sig, NUMBER_OF_MESSAGES);

    assert(execute_PoK_of_message_protocol_and_obtain_signature(&sig, message, &user_pk, &user_sk, &signer_sk, prng));

    PoK_randomness randomness;
    BIG_256_56_random(randomness.r, prng);

    compute_blind_signature(&blind_sig, &sig, &randomness, prng);

    assert(execute_PoK_of_signature_and_verify_pairings(&blind_sig, &signer_pk, &randomness, message, prng));// ? res++ : (res = 0);

    schemeD_destroy_keypair(&user_sk, &user_pk);
    schemeD_destroy_keypair(&signer_sk, &signer_pk);
    schemeD_destroy_signature(&sig);

    printf("Success\n");
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


    printf("Testing anonymous credentials...");
    test_anonymous_credentials(&prng);

    return 0;
}
