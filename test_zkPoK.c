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
    if( ! verifier(&T, &commitment, s, challenge, user_pk)) return 0;

    ECP_BN254 converted_commitment;

    commitment_conversion(&converted_commitment, user_sk, sig, message);

    sign_commitment(sig, &converted_commitment, signer_sk, prng);

    return 1;
}

void test_zkPoK(csprng *prng) {
    int res = 0;

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
    schemeD_sig sig;
    schemeD_init_signature(&sig, NUMBER_OF_MESSAGES);

    execute_PoK_of_message_protocol_and_obtain_signature(&sig, message, &user_pk, &user_sk, &signer_sk, prng) ? res++ : (res = 0);

    //Compute blind singature
    schemeD_sig blind_sig;
    schemeD_init_signature(&blind_sig, NUMBER_OF_MESSAGES);

    PoK_proof proof;
    BIG_256_56_random(proof.r, prng);

    PoK_compute_blind_signature(&blind_sig, &sig, &proof, prng);

    FP12_BN254 commitment_2;

    PoK_generate_commitment(&commitment_2, &proof, message, &signer_pk, &blind_sig);

    FP12_BN254 T_2;
    BIG_256_56 t1;
    BIG_256_56 t2[NUMBER_OF_MESSAGES];

    PoK_prover_1(&T_2, t1, t2, &signer_pk, &blind_sig, prng);

    BIG_256_56 s1, challenge_2;
    BIG_256_56 s2[NUMBER_OF_MESSAGES];

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
    

    printf("Testing signature_on_committed_value_2...");
    test_zkPoK(&prng);

    return 0;
}
