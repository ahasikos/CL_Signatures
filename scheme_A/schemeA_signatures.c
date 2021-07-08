//
// Created by Alexandros Hasikos on 08/07/2021.
//

#include "schemeA_signatures.h"

#include <string.h>
#include <pair_BN254.h>

void schemeA_init_sk(schemeA_secret_key *sk) {
    memset(sk->x_mem, 0, sizeof(sk->x_mem));
    memset(sk->y_mem, 0, sizeof(sk->y_mem));

    sk->x.len = 0;
    sk->x.max = sizeof(sk->x_mem);
    sk->x.val = sk->x_mem;

    sk->y.len = 0;
    sk->y.max = sizeof(sk->y_mem);
    sk->y.val = sk->y_mem;
}

void schemeA_generate_sk(schemeA_secret_key *sk, csprng *prng) {
    BIG_256_56_random(sk->x_big, prng);
    BIG_256_56_random(sk->y_big, prng);

}

void schemeA_generate_pk(schemeA_public_key *pk, schemeA_secret_key *sk) {
    ECP2_BN254_generator(&pk->g_2);
    ECP2_BN254_copy(&pk->Y, &pk->g_2);
    ECP2_BN254_copy(&pk->X, &pk->g_2);

    PAIR_BN254_G2mul(&pk->X, sk->x_big);
    PAIR_BN254_G2mul(&pk->Y, sk->y_big);
}

void schemeA_sign(schemeA_signature *sig, BIG_256_56 message, schemeA_secret_key *sk, csprng *prng) {
    //Generate random element
    FP_BN254 rnd;
    FP_BN254_rand(&rnd, prng);

    //Map element to point and compute a
    ECP_BN254_map2point(&sig->a, &rnd);

    // Compute a^y
    ECP_BN254_copy(&sig->b, &sig->a);
    PAIR_BN254_G1mul(&sig->b, sk->y_big);

    //Compute a^(x + mxy)
    BIG_256_56 m_times_x, mx_times_y, x_plus_mxy;

    BIG_256_56_modmul(m_times_x, message, sk->x_big, (int64_t *)CURVE_Order_BN254);
    BIG_256_56_modmul(mx_times_y, m_times_x, sk->y_big, (int64_t *)CURVE_Order_BN254);
    BIG_256_56_modadd(x_plus_mxy, mx_times_y, sk->x_big, (int64_t *)CURVE_Order_BN254);

    ECP_BN254_copy(&sig->c, &sig->a);
    PAIR_BN254_G1mul(&sig->c, x_plus_mxy);
}

int schemeA_verify(schemeA_signature *sig, BIG_256_56 message, schemeA_public_key *pk) {
    //Verification 1
    FP12_BN254 p1, p2;

    PAIR_BN254_ate(&p1, &pk->Y, &sig->a);
    PAIR_BN254_fexp(&p1);

    PAIR_BN254_ate(&p2, &pk->g_2, &sig->b);
    PAIR_BN254_fexp(&p2);

    //Verification 2
    FP12_BN254 p3, p4;

    PAIR_BN254_ate(&p3, &pk->X, &sig->a);
    PAIR_BN254_fexp(&p3);

    PAIR_BN254_G1mul(&sig->b, message);
    PAIR_BN254_ate(&p4, &pk->X, &sig->b);
    PAIR_BN254_fexp(&p4);

    FP12_BN254 lhs;
    FP12_BN254_copy(&lhs, &p3);
    FP12_BN254_mul(&lhs, &p4);

    FP12_BN254 rhs;
    PAIR_BN254_ate(&rhs, &pk->g_2, &sig->c);
    PAIR_BN254_fexp(&rhs);

    if( (FP12_BN254_equals(&p1, &p2) == 1) &&
        (FP12_BN254_equals(&lhs, &rhs)) == 1 ){
        return 1;
    } else {
        return 0;
    }
}
