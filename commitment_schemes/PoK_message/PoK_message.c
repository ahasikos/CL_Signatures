//
// Created by Alexandros Hasikos on 21/07/2021.
//

#include <pair_BN254.h>
#include <signatures/schemeD/schemeD.h>
#include <params.h>

#include "PoK_message.h"

void generate_commitment(ECP2_BN254 *commitment, BIG_256_56 *message, schemeD_pk *public_key) {
    ECP2_BN254 g_times_m_zero;

    ECP2_BN254_copy(&g_times_m_zero, &public_key->g_2);
    PAIR_BN254_G2mul(&g_times_m_zero, message[0]);

    ECP2_BN254_copy(commitment, &g_times_m_zero);

    ECP2_BN254 g_times_zi_times_mi, sum;
    ECP2_BN254_inf(&sum);

    for(int i = 1; i < public_key->l; i++) {
        ECP2_BN254_copy(&g_times_zi_times_mi, &public_key->Z[i]);
        PAIR_BN254_G2mul(&g_times_zi_times_mi, message[i]);

        ECP2_BN254_add(&sum, &g_times_zi_times_mi);
    }

    ECP2_BN254_add(commitment, &sum);
}

void commitment_conversion(ECP_BN254 *commitment, schemeD_sk *sk, schemeD_sig *sig, BIG_256_56 *message) {

    ECP_BN254 g_times_m_zero;

    ECP_BN254_generator(&g_times_m_zero);
    PAIR_BN254_G1mul(&g_times_m_zero, message[0]);

    ECP_BN254_copy(commitment, &g_times_m_zero);

    ECP_BN254 g_times_zi_times_mi, sum;
    BIG_256_56 zi_times_mi;
    ECP_BN254_inf(&sum);

    for(int i = 1; i < sk->l; i++) {
        BIG_256_56_modmul(zi_times_mi, sk->z[i], message[i], MODULUS);

        ECP_BN254_generator(&g_times_zi_times_mi);
        PAIR_BN254_G1mul(&g_times_zi_times_mi, zi_times_mi);

        ECP_BN254_add(&sum, &g_times_zi_times_mi);
    }

    ECP_BN254_add(commitment, &sum);
}

void prover_1(ECP2_BN254 *T, BIG_256_56 *t, schemeD_pk *public_key, csprng *prng) {

    //Generate t
    for(int i = 0; i < public_key->l; i++) {
        BIG_256_56_random(t[i], prng);
    }

    ECP2_BN254 g_times_t_zero;

    ECP2_BN254_copy(&g_times_t_zero, &public_key->g_2);
    PAIR_BN254_G2mul(&g_times_t_zero, t[0]);

    ECP2_BN254_copy(T, &g_times_t_zero);

    ECP2_BN254 Z_i_times_t_i, sum;
    ECP2_BN254_inf(&sum);

    for(int i = 1; i < public_key->l; i++) {
        ECP2_BN254_copy(&Z_i_times_t_i, &public_key->Z[i]);
        PAIR_BN254_G2mul(&Z_i_times_t_i, t[i]);

        ECP2_BN254_add(&sum, &Z_i_times_t_i);
    }

    ECP2_BN254_add(T, &sum);
}

void prover_2(BIG_256_56 *s, BIG_256_56 c, BIG_256_56 *t, BIG_256_56 *message, uint32_t mlen) {
    BIG_256_56 m_i_times_c, m_i_times_c_plus_t_i;

    for(int i = 0; i < mlen; i++) {
        BIG_256_56_modmul(m_i_times_c, message[i], c, (int64_t *)CURVE_Order_BN254);
        BIG_256_56_modadd(m_i_times_c_plus_t_i, m_i_times_c, t[i], (int64_t *)CURVE_Order_BN254);

        BIG_256_56_copy(s[i], m_i_times_c_plus_t_i);
    }
}

int verifier(ECP2_BN254 *T, ECP2_BN254 *commitment, BIG_256_56 *s, BIG_256_56 c, schemeD_pk *public_key) {

    ECP2_BN254 rhs, g_times_s_zero;

    ECP2_BN254_copy(&g_times_s_zero, &public_key->g_2);
    PAIR_BN254_G2mul(&g_times_s_zero, s[0]);

    ECP2_BN254_copy(&rhs, &g_times_s_zero);

    ECP2_BN254 Z_i_times_s_i, sum;
    ECP2_BN254_inf(&sum);

    for(int i = 1; i < public_key->l; i++) {
        ECP2_BN254_copy(&Z_i_times_s_i, &public_key->Z[i]);
        PAIR_BN254_G2mul(&Z_i_times_s_i, s[i]);

        ECP2_BN254_add(&sum, &Z_i_times_s_i);
    }

    ECP2_BN254_add(&rhs, &sum);

    ECP2_BN254 M_times_c, lhs;

    ECP2_BN254_copy(&M_times_c, commitment);
    PAIR_BN254_G2mul(&M_times_c, c);

    ECP2_BN254_add(&M_times_c, T);
    ECP2_BN254_copy(&lhs, &M_times_c);

    if(ECP2_BN254_equals(&rhs, &lhs)) return 1;

    return 0;
}