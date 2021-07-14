//
// Created by Alexandros Hasikos on 09/07/2021.
//

#include "schemeC_signatures.h"
#include <pair_BN254.h>
#include <string.h>

void schemeC_init_secret_key(schemeC_secret_key *sk, BIG_256_56 *buf, uint32_t number_of_messages) {
    sk->l = number_of_messages;
    sk->z_big = buf;
}

void schemeC_init_public_key(schemeC_public_key *pk, ECP2_BN254 *buf, uint32_t number_of_messages) {
    pk->l = number_of_messages;
    pk->Z = buf;
}

void schemeC_init_signature(schemeC_signature *sig, ECP_BN254 *buf_A, ECP_BN254 *buf_B, uint32_t number_of_messages) {
    sig->l = number_of_messages;
    sig->A = buf_A;
    sig->B = buf_B;
}

void schemeC_generate_sk(schemeC_secret_key *sk, csprng *prng) {
    BIG_256_56_random(sk->x_big, prng);
    BIG_256_56_random(sk->y_big, prng);

    for(int i = 0; i < sk->l; i++) {
        BIG_256_56_random(sk->z_big[i], prng);
    }
}

void schemeC_generate_pk(schemeC_public_key *pk, schemeC_secret_key *sk) {
    ECP2_BN254_generator(&pk->g_2);

    ECP2_BN254_copy(&pk->Y, &pk->g_2);
    ECP2_BN254_copy(&pk->X, &pk->g_2);

    PAIR_BN254_G2mul(&pk->X, sk->x_big);
    PAIR_BN254_G2mul(&pk->Y, sk->y_big);

    for(int i = 0; i < pk->l; i++) {
        ECP2_BN254_copy(&pk->Z[i], &pk->g_2);
        PAIR_BN254_G2mul(&pk->Z[i], sk->z_big[i]);
    }
}

void schemeC_sign(schemeC_signature *sig, BIG_256_56 *message, schemeC_secret_key *sk, csprng *prng) {
    //Generate random element
    FP_BN254 rnd;
    FP_BN254_rand(&rnd, prng);

    //Map element to point and compute a
    ECP_BN254_map2point(&sig->a, &rnd);

    //Compute A[i] -> a^z[i] and B[i] -> A[i]^y
    for(int i = 0; i < sk->l; i++) {
        ECP_BN254_copy(&sig->A[i], &sig->a);
        PAIR_BN254_G1mul(&sig->A[i], sk->z_big[i]);

        ECP_BN254_copy(&sig->B[i], &sig->A[i]);
        PAIR_BN254_G1mul(&sig->B[i], sk->y_big);
    }

    // Compute b -> a^y
    ECP_BN254_copy(&sig->b, &sig->a);
    PAIR_BN254_G1mul(&sig->b, sk->y_big);

    //Compute c-> a^(x + mxy) * A^(xyr)
    BIG_256_56 m_times_x, mx_times_y, x_plus_mxy, x_times_y;
    ECP_BN254 a_times_x_plus_xym;

    BIG_256_56_modmul(m_times_x, message[0], sk->x_big, (int64_t *)CURVE_Order_BN254);
    BIG_256_56_modmul(mx_times_y, m_times_x, sk->y_big, (int64_t *)CURVE_Order_BN254);
    BIG_256_56_modadd(x_plus_mxy, mx_times_y, sk->x_big, (int64_t *)CURVE_Order_BN254);

    ECP_BN254_copy(&a_times_x_plus_xym, &sig->a);
    PAIR_BN254_G1mul(&a_times_x_plus_xym, x_plus_mxy);


    BIG_256_56 xy_times_m_i;
    ECP_BN254 product_A_times_xym_i, sum;
    BIG_256_56_modmul(x_times_y, sk->x_big, sk->y_big, (int64_t *)CURVE_Order_BN254);

    //Iteration 1
    BIG_256_56_modmul(xy_times_m_i, x_times_y, message[1], (int64_t *)CURVE_Order_BN254);

    ECP_BN254_copy(&product_A_times_xym_i, &sig->A[1]);
    PAIR_BN254_G1mul(&product_A_times_xym_i, xy_times_m_i);

    ECP_BN254_copy(&sum, &product_A_times_xym_i);

    for(int i = 2; i < sk->l; i++) {
        BIG_256_56_modmul(xy_times_m_i, x_times_y, message[i], (int64_t *)CURVE_Order_BN254);

        ECP_BN254_copy(&product_A_times_xym_i, &sig->A[i]);
        PAIR_BN254_G1mul(&product_A_times_xym_i, xy_times_m_i);

        ECP_BN254_add(&sum, &product_A_times_xym_i);
    }

    // Multiply the two
    ECP_BN254_copy(&sig->c, &a_times_x_plus_xym);
    ECP_BN254_add(&sig->c, &sum);
}

int schemeC_verify(schemeC_signature *sig, BIG_256_56 *message, schemeC_public_key *pk) {
    //Verification 1
    FP12_BN254 p1, p2;
    int v1 = 0;

    for(int i = 0; i < pk->l; i++) {
        PAIR_BN254_ate(&p1, &pk->Z[i], &sig->a);
        PAIR_BN254_fexp(&p1);

        PAIR_BN254_ate(&p2, &pk->g_2, &sig->A[i]);
        PAIR_BN254_fexp(&p2);

        if(FP12_BN254_equals(&p1, &p2)) v1 = 1;
    }

    //Verification 2
    FP12_BN254 p3, p4, p5, p6;
    int v2, v2_1 = 0;

    PAIR_BN254_ate(&p3, &pk->Y, &sig->a);
    PAIR_BN254_fexp(&p3);

    PAIR_BN254_ate(&p4, &pk->g_2, &sig->b);
    PAIR_BN254_fexp(&p4);

    if(FP12_BN254_equals(&p3, &p3)) v2 = 1;

    for(int i = 0; i < pk->l; i++) {
        PAIR_BN254_ate(&p5, &pk->Y, &sig->A[i]);
        PAIR_BN254_fexp(&p5);

        PAIR_BN254_ate(&p6, &pk->g_2, &sig->B[i]);
        PAIR_BN254_fexp(&p6);

        if(FP12_BN254_equals(&p5, &p6)) v2_1 = 1;

    }

    //Verification 3
    FP12_BN254 p7, p8, p9, p10;
    ECP_BN254 tmp_b;
    int v3 = 0;

    PAIR_BN254_ate(&p7, &pk->X, &sig->a);
    PAIR_BN254_fexp(&p7);

    ECP_BN254_copy(&tmp_b, &sig->b);
    PAIR_BN254_G1mul(&tmp_b, message[0]);
    PAIR_BN254_ate(&p8, &pk->X, &tmp_b);
    PAIR_BN254_fexp(&p8);


    ECP_BN254 B_i_times_m_i;
    //Iteration 1
    ECP_BN254_copy(&B_i_times_m_i, &sig->B[1]);
    PAIR_BN254_G1mul(&B_i_times_m_i, message[1]);

    PAIR_BN254_ate(&p9, &pk->X, &B_i_times_m_i);
    PAIR_BN254_fexp(&p9);

    FP12_BN254_copy(&p10, &p9);

    for(int i = 2; i < pk->l; i++) {
        ECP_BN254_copy(&B_i_times_m_i, &sig->B[i]);
        PAIR_BN254_G1mul(&B_i_times_m_i, message[i]);

        PAIR_BN254_ate(&p9, &pk->X, &B_i_times_m_i);
        PAIR_BN254_fexp(&p9);

        FP12_BN254_mul(&p10, &p9);
    }

    // Multiply the three
    FP12_BN254 lhs;
    FP12_BN254_copy(&lhs, &p7);
    FP12_BN254_mul(&lhs, &p8);
    FP12_BN254_mul(&lhs, &p10);

    FP12_BN254 rhs;
    PAIR_BN254_ate(&rhs, &pk->g_2, &sig->c);
    PAIR_BN254_fexp(&rhs);

    if(FP12_BN254_equals(&lhs, &rhs)) v3 = 1;

    if (v1 &&
        v2 &&
        v2_1 &&
        v3) {
        return 1;
    }

    return 0;
}