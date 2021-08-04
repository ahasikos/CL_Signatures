//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include "schemeD.h"
#include <utils/utils.h>
#include <pair_BN254.h>
#include <string.h>

void schemeD_init_secret_key(schemeD_secret_key *sk, BIG_256_56 *buf, uint32_t number_of_messages) {
    sk->l = number_of_messages;
    sk->z = buf;
}

void
schemeD_init_public_key(schemeD_public_key *pk, ECP2_BN254 *Z_buf, ECP2_BN254 *W_buf, uint32_t number_of_messages) {
    pk->l = number_of_messages;
    pk->Z = Z_buf;
    pk->W = W_buf;
}

void schemeD_init_signature(schemeD_signature *sig, ECP_BN254 *buf_A, ECP_BN254 *buf_B, uint32_t number_of_messages) {
    sig->l = number_of_messages;
    sig->A = buf_A;
    sig->B = buf_B;
}

void schemeD_generate_sk(schemeD_secret_key *sk, csprng *prng) {
    BIG_256_56_random(sk->x, prng);
    BIG_256_56_random(sk->y, prng);

    for(int i = 0; i < sk->l; i++) {
        BIG_256_56_random(sk->z[i], prng);
    }
}

void schemeD_generate_pk(schemeD_public_key *pk, schemeD_secret_key *sk) {
    ECP2_BN254_generator(&pk->g_2);
    ECP_BN254_generator(&pk->g);

    ECP2_BN254_copy(&pk->Y, &pk->g_2);
    ECP2_BN254_copy(&pk->X, &pk->g_2);

    PAIR_BN254_G2mul(&pk->X, sk->x);
    PAIR_BN254_G2mul(&pk->Y, sk->y);

    for(int i = 0; i < pk->l; i++) {
        ECP2_BN254_copy(&pk->Z[i], &pk->g_2);
        PAIR_BN254_G2mul(&pk->Z[i], sk->z[i]);

        ECP2_BN254_copy(&pk->W[i], &pk->Y);
        PAIR_BN254_G2mul(&pk->W[i], sk->z[i]);
    }
}

void schemeD_sign(schemeD_signature *sig, BIG_256_56 *message, schemeD_secret_key *sk, csprng *prng) {
    //Generate random element
    FP_BN254 rnd;
    FP_BN254_rand(&rnd, prng);

    //Map element to point and compute a
    ECP_BN254_map2point(&sig->a, &rnd);

    //Compute A[i] -> a^z[i] and B[i] -> A[i]^y
    for(int i = 0; i < sk->l; i++) {
        ECP_BN254_copy(&sig->A[i], &sig->a);
        PAIR_BN254_G1mul(&sig->A[i], sk->z[i]);

        ECP_BN254_copy(&sig->B[i], &sig->A[i]);
        PAIR_BN254_G1mul(&sig->B[i], sk->y);
    }

    // Compute b -> a^y
    ECP_BN254_copy(&sig->b, &sig->a);
    PAIR_BN254_G1mul(&sig->b, sk->y);

    //Compute c-> a^(x + mxy) * A^(xyr)
    BIG_256_56 x_plus_xym, x_times_y, xym;
    ECP_BN254 a_times_x_plus_xym;

    BIG_256_56_mul_xyz(&xym, sk->x, sk->y, message[0]);
    BIG_256_56_modadd(x_plus_xym, xym, sk->x, (int64_t *)CURVE_Order_BN254);

    ECP_BN254_copy(&a_times_x_plus_xym, &sig->a);
    PAIR_BN254_G1mul(&a_times_x_plus_xym, x_plus_xym);


    BIG_256_56 xy_times_m_i;
    ECP_BN254 product_A_times_xym_i, sum;
    ECP_BN254_inf(&sum);

    BIG_256_56_modmul(x_times_y, sk->x, sk->y, (int64_t *)CURVE_Order_BN254);

    for(int i = 1; i < sk->l; i++) {
        BIG_256_56_modmul(xy_times_m_i, x_times_y, message[i], (int64_t *)CURVE_Order_BN254);

        ECP_BN254_copy(&product_A_times_xym_i, &sig->A[i]);
        PAIR_BN254_G1mul(&product_A_times_xym_i, xy_times_m_i);

        ECP_BN254_add(&sum, &product_A_times_xym_i);
    }
    // Multiply the two
    ECP_BN254_copy(&sig->c, &a_times_x_plus_xym);
    ECP_BN254_add(&sig->c, &sum);
}

int schemeD_verify(schemeD_signature *sig, BIG_256_56 *message, schemeD_public_key *pk) {
    int res = 0, v1 = 0, v2 = 0;

    //Verification 1
    for(int i = 0; i < pk->l; i++) {
        v1 += pairing_and_equality_check(&pk->Z[i], &sig->a, &pk->g_2, &sig->A[i]);
    }

    if( v1 == pk->l ) res ++;

    //Verification 2
    res += pairing_and_equality_check(&pk->Y, &sig->a, &pk->g_2, &sig->b);

    //Verification 3
    for(int i = 0; i < pk->l; i++) {
        v2 += pairing_and_equality_check(&pk->Y, &sig->A[i], &pk->g_2, &sig->B[i]);
    }

    if( v2 == pk->l ) res++;

    //Verification 4
    FP12_BN254 inner_element, inner_product, Xa_times_Xb, rhs, lhs;
    ECP_BN254 b_times_m_0, B_i_times_m_i;

    FP12_BN254_one(&inner_product);

    ECP_BN254_copy(&b_times_m_0, &sig->b);
    PAIR_BN254_G1mul(&b_times_m_0, message[0]);

    two_element_pairing_and_multiplication(&Xa_times_Xb, &pk->X, &sig->a, &pk->X, &b_times_m_0);

    for(int i = 1; i < pk->l; i++) {
        ECP_BN254_copy(&B_i_times_m_i, &sig->B[i]);
        PAIR_BN254_G1mul(&B_i_times_m_i, message[i]);

        PAIR_BN254_ate(&inner_element, &pk->X, &B_i_times_m_i);
        PAIR_BN254_fexp(&inner_element);

        FP12_BN254_mul(&inner_product, &inner_element);
    }

    // Multiply the three
    FP12_BN254_copy(&lhs, &Xa_times_Xb);
    FP12_BN254_mul(&lhs, &inner_product);

    PAIR_BN254_ate(&rhs, &pk->g_2, &sig->c);
    PAIR_BN254_fexp(&rhs);

    res += FP12_BN254_equals(&lhs, &rhs);

    if (res == 4 ) return 1;

    return 0;
}
