//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include <ecp_BN254.h>
#include <pair_BN254.h>
#include "utils.h"

void BIG_256_56_mul_xyz(BIG_256_56 *res, BIG_256_56 x, BIG_256_56 y, BIG_256_56 z) {
    BIG_256_56_modmul(*res, x, y, (int64_t *)CURVE_Order_BN254);
    BIG_256_56_modmul(*res, *res, z, (int64_t *)CURVE_Order_BN254);
}

int pairing_and_equality_check(ECP2_BN254 *ecp2_point_1, ECP_BN254 *ecp_point_1, ECP2_BN254 *ecp2_point_2,
                               ECP_BN254 *ecp_point_2) {
    FP12_BN254 p1, p2;

    PAIR_BN254_ate(&p1, ecp2_point_1, ecp_point_1);
    PAIR_BN254_fexp(&p1);

    PAIR_BN254_ate(&p2, ecp2_point_2, ecp_point_2);
    PAIR_BN254_fexp(&p2);

    return FP12_BN254_equals(&p1, &p2);
}

void two_element_pairing_and_multiplication(FP12_BN254 *res, ECP2_BN254 *ecp2_point_1, ECP_BN254 *ecp_point_1, ECP2_BN254 *ecp2_point_2,
                                            ECP_BN254 *ecp_point_2) {

    FP12_BN254 p1, p2;

    PAIR_BN254_ate(&p1, ecp2_point_1, ecp_point_1);
    PAIR_BN254_fexp(&p1);

    PAIR_BN254_ate(&p2, ecp2_point_2, ecp_point_2);
    PAIR_BN254_fexp(&p2);

    FP12_BN254_copy(res, &p1);
    FP12_BN254_mul(res, &p2);
}

void three_element_pairing_and_multiplication(FP12_BN254 *res, ECP2_BN254 *ecp2_point_1, ECP_BN254 *ecp_point_1, ECP2_BN254 *ecp2_point_2,
                                              ECP_BN254 *ecp_point_2, ECP2_BN254 *ecp2_point_3, ECP_BN254 *ecp_point_3) {

    FP12_BN254 p1, p2, p3;

    PAIR_BN254_ate(&p1, ecp2_point_1, ecp_point_1);
    PAIR_BN254_fexp(&p1);

    PAIR_BN254_ate(&p2, ecp2_point_2, ecp_point_2);
    PAIR_BN254_fexp(&p2);

    PAIR_BN254_ate(&p3, ecp2_point_3, ecp_point_3);
    PAIR_BN254_fexp(&p3);

    FP12_BN254_copy(res, &p1);
    FP12_BN254_mul(res, &p2);
    FP12_BN254_mul(res, &p3);
}
