//
// Created by Alexandros Hasikos on 08/07/2021.
//

#include "schemeA.h"
#include <utils/utils.h>

#include <string.h>
#include <pair_BN254.h>
#include <params.h>

void schemeA_generate_sk(schemeA_sk *sk, csprng *prng) {
    BIG_256_56_random(sk->x, prng);
    BIG_256_56_random(sk->y, prng);
}

void schemeA_generate_pk(schemeA_pk *pk, schemeA_sk *sk) {
    ECP2_BN254_generator(&pk->Y);
    ECP2_BN254_generator(&pk->X);

    PAIR_BN254_G2mul(&pk->X, sk->x);
    PAIR_BN254_G2mul(&pk->Y, sk->y);
}

void schemeA_sign(schemeA_sig *sig, BIG_256_56 message, schemeA_sk *sk, csprng *prng) {
    //Generate random element
    FP_BN254 rnd;
    FP_BN254_rand(&rnd, prng);

    //Map element to point and compute a
    ECP_BN254_map2point(&sig->a, &rnd);

    // Compute a^y
    ECP_BN254_copy(&sig->b, &sig->a);
    PAIR_BN254_G1mul(&sig->b, sk->y);

    //Compute a^(x + xym)
    BIG_256_56 x_plus_xym, xym;

    BIG_256_56_mul_xyz(&xym, sk->x, sk->y, message);
    BIG_256_56_modadd(x_plus_xym, xym, sk->x, MODULUS);

    ECP_BN254_copy(&sig->c, &sig->a);
    PAIR_BN254_G1mul(&sig->c, x_plus_xym);
}

int schemeA_verify(schemeA_sig *sig, BIG_256_56 message, schemeA_pk *pk) {
    int res = 0;

    ECP2_BN254 G2;
    ECP2_BN254_generator(&G2);

    //Verification 1
    res += pairing_and_equality_check(&pk->Y, &sig->a, &G2, &sig->b);

    //Verification 2
    FP12_BN254 lhs, rhs;
    ECP_BN254 b_times_m;

    ECP_BN254_copy(&b_times_m, &sig->b);
    PAIR_BN254_G1mul(&b_times_m, message);

    two_element_pairing_and_multiplication(&lhs, &pk->X, &sig->a, &pk->X, &b_times_m);

    PAIR_BN254_ate(&rhs, &G2, &sig->c);
    PAIR_BN254_fexp(&rhs);

    res += FP12_BN254_equals(&lhs, &rhs);

    if( res == 2 ) return 1;

    return 0;
}
