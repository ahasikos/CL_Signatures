//
// Created by Alexandros Hasikos on 09/07/2021.
//

#include "schemeB_signatures.h"
#include <pair_BN254.h>

void schemeB_generate_sk(schemeB_secret_key *sk, csprng *prng) {
    BIG_256_56_random(sk->x_big, prng);
    BIG_256_56_random(sk->y_big, prng);
    BIG_256_56_random(sk->z_big, prng);
}

void schemeB_generate_pk(schemeB_public_key *pk, schemeB_secret_key *sk) {
    ECP2_BN254_generator(&pk->g_2);

    ECP2_BN254_copy(&pk->Y, &pk->g_2);
    ECP2_BN254_copy(&pk->X, &pk->g_2);
    ECP2_BN254_copy(&pk->Z, &pk->g_2);

    PAIR_BN254_G2mul(&pk->X, sk->x_big);
    PAIR_BN254_G2mul(&pk->Y, sk->y_big);
    PAIR_BN254_G2mul(&pk->Z, sk->z_big);
}

void schemeB_sign(schemeB_signature *sig, BIG_256_56 message, BIG_256_56 randomness, schemeB_secret_key *sk, csprng *prng) {
    //Generate random element
    FP_BN254 rnd;
    FP_BN254_rand(&rnd, prng);

    //Map element to point and compute a
    ECP_BN254_map2point(&sig->a, &rnd);

    //Compute A -> a^z
    ECP_BN254_copy(&sig->A, &sig->a);
    PAIR_BN254_G1mul(&sig->A, sk->z_big);

    // Compute b -> a^y
    ECP_BN254_copy(&sig->b, &sig->a);
    PAIR_BN254_G1mul(&sig->b, sk->y_big);

    //Compute B -> A^y
    ECP_BN254_copy(&sig->B, &sig->A);
    PAIR_BN254_G1mul(&sig->B, sk->y_big);

    //Compute c-> a^(x + mxy) * A^(xyr)
    BIG_256_56 m_times_x, mx_times_y, x_plus_mxy, x_times_y, xy_times_r;
    ECP_BN254 a_times_x_plus_xym, A_times_xyr;

    BIG_256_56_modmul(m_times_x, message, sk->x_big, (int64_t *)CURVE_Order_BN254);
    BIG_256_56_modmul(mx_times_y, m_times_x, sk->y_big, (int64_t *)CURVE_Order_BN254);
    BIG_256_56_modadd(x_plus_mxy, mx_times_y, sk->x_big, (int64_t *)CURVE_Order_BN254);

    ECP_BN254_copy(&a_times_x_plus_xym, &sig->a);
    PAIR_BN254_G1mul(&a_times_x_plus_xym, x_plus_mxy);

    BIG_256_56_modmul(x_times_y, sk->x_big, sk->y_big, (int64_t *)CURVE_Order_BN254);
    BIG_256_56_modmul(xy_times_r, x_times_y, randomness, (int64_t *)CURVE_Order_BN254);

    ECP_BN254_copy(&A_times_xyr, &sig->A);
    PAIR_BN254_G1mul(&A_times_xyr, xy_times_r);

    // Multiply the two
    ECP_BN254_copy(&sig->c, &a_times_x_plus_xym);
    ECP_BN254_add(&sig->c, &A_times_xyr);
}

int schemeB_verify(schemeB_signature *sig, BIG_256_56 message, BIG_256_56 randomness, schemeB_public_key *pk) {
    //Verification 1
    FP12_BN254 p1, p2;

    PAIR_BN254_ate(&p1, &pk->Z, &sig->a);
    PAIR_BN254_fexp(&p1);

    PAIR_BN254_ate(&p2, &pk->g_2, &sig->A);
    PAIR_BN254_fexp(&p2);

    //Verification 2
    FP12_BN254 p3, p4, p5, p6;

    PAIR_BN254_ate(&p3, &pk->Y, &sig->a);
    PAIR_BN254_fexp(&p3);

    PAIR_BN254_ate(&p4, &pk->g_2, &sig->b);
    PAIR_BN254_fexp(&p4);

    PAIR_BN254_ate(&p5, &pk->Y, &sig->A);
    PAIR_BN254_fexp(&p5);

    PAIR_BN254_ate(&p6, &pk->g_2, &sig->B);
    PAIR_BN254_fexp(&p6);

    //Verification 3
    FP12_BN254 p7, p8, p9;

    PAIR_BN254_ate(&p7, &pk->X, &sig->a);
    PAIR_BN254_fexp(&p7);

    PAIR_BN254_G1mul(&sig->b, message);
    PAIR_BN254_ate(&p8, &pk->X, &sig->b);
    PAIR_BN254_fexp(&p8);

    PAIR_BN254_G1mul(&sig->B, randomness);
    PAIR_BN254_ate(&p9, &pk->X, &sig->B);
    PAIR_BN254_fexp(&p9);

    FP12_BN254 lhs;
    FP12_BN254_copy(&lhs, &p7);
    FP12_BN254_mul(&lhs, &p8);
    FP12_BN254_mul(&lhs, &p9);

    FP12_BN254 rhs;
    PAIR_BN254_ate(&rhs, &pk->g_2, &sig->c);
    PAIR_BN254_fexp(&rhs);

    if( (FP12_BN254_equals(&p1, &p2) == 1) &&
        (FP12_BN254_equals(&p3, &p4)) &&
        (FP12_BN254_equals(&p5, &p6)) &&
        (FP12_BN254_equals(&lhs, &rhs)) == 1 ){
        return 1;
    }
    return 0;
}