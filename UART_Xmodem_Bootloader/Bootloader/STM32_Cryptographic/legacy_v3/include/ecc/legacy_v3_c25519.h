/**
  ******************************************************************************
  * @file    legacy_v3_c25519.h
  * @author  MCD Application Team
  * @brief   Header file of Curve25519 helper for migration of cryptographics
  *          library V3 to V4
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

#ifndef CMOX_HELPER_C25519_H
#define CMOX_HELPER_C25519_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/**
  * @brief         X25519 key generation function
  * @param[in,out] *P_pPrivateKey           Buffer of 32 random bytes, which will hold the Private Key
  * @param[out]    *P_pPublicKey            Buffer of 32 bytes which will hold the Public Key
  * @retval        C25519_SUCCESS           Key Pair generated successfully
  * @retval        C25519_ERR_BAD_PARAMETER P_pPrivateKey == NULL or P_pPublicKey == NULL
  * @note          P_pPrivateKey must contain 32 random bytes that will be used for the key pair generation
  */
int32_t C25519keyGen(uint8_t *P_pPrivateKey, uint8_t *P_pPublicKey);

/**
  * @brief      X25519 key exchange function
  * @param[out] *P_pSharedSecret Buffer of 32 bytes which will store the shared secret
  * @param[in]  *P_pPrivateKey   Buffer of 32 bytes containing the Private Key
  * @param[in]  *P_pPublicKey    Buffer of 32 bytes containing the other party's Public Key
  * @retval     C25519_SUCCESS           Shared secret generated successfully
  * @retval     C25519_ERR_BAD_PARAMETER Some parameter is NULL
  * @remark     The user should hash the resulting Shared Secret before using it
  */
int32_t C25519keyExchange(uint8_t *P_pSharedSecret, const uint8_t *P_pPrivateKey, const uint8_t *P_pPublicKey);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CMOX_HELPER_C25519_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
