//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_UTILS_H
#define CL_SIGNATURES_UTILS_H

#include <big_256_56.h>
#include <fp12_BN254.h>

void BIG_256_56_mul_xyz(BIG_256_56 *res, BIG_256_56 x, BIG_256_56 y, BIG_256_56 z);

int pairing_and_equality_check(ECP2_BN254 *ecp2_point_1, ECP_BN254 *ecp_point_1, ECP2_BN254 *ecp2_point_2,
                               ECP_BN254 *ecp_point_2);

void two_element_pairing_and_multiplication(FP12_BN254 *res, ECP2_BN254 *ecp2_point_1, ECP_BN254 *ecp_point_1, ECP2_BN254 *ecp2_point_2,
                                            ECP_BN254 *ecp_point_2);

void three_element_pairing_and_multiplication(FP12_BN254 *res, ECP2_BN254 *ecp2_point_1, ECP_BN254 *ecp_point_1, ECP2_BN254 *ecp2_point_2,
                                ECP_BN254 *ecp_point_2, ECP2_BN254 *ecp2_point_3, ECP_BN254 *ecp_point_3);

#endif //CL_SIGNATURES_UTILS_H
