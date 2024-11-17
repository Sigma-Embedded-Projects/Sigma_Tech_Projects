/**
  ******************************************************************************
  * @file    legacy_v3_c25519.c
  * @author  MCD Application Team
  * @brief   This file provides C25519 functions of helper for migration
  *          of cryptographics library V3 to V4
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

#include "ecc/cmox_ecdh.h"
#include "err_codes.h"
#include "ecc/legacy_v3_c25519.h"

/* X25519 key exchange function */
int32_t C25519keyExchange(uint8_t *P_pSharedSecret, const uint8_t *P_pPrivateKey, const uint8_t *P_pPublicKey)
{
  cmox_ecc_handle_t ctx; /* CLv4 internal ECC context */
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */
  uint8_t buf[496 + 68]; /* CLv4 internal memory buffer */
  int32_t retval = C25519_ERR_BAD_PARAMETER; /* by default, return error */
  size_t ss_len;

  /* set the internal memory buffer and the default math engine */
  cmox_ecc_construct(&ctx, CMOX_ECC256_MATH_FUNCS, buf, sizeof(buf));

  /* perform X25519 key exchange with CLv4 */
  cmox_rv = cmox_ecdh(&ctx, CMOX_ECC_CURVE25519,
                      P_pPrivateKey, 32u,
                      P_pPublicKey, 32u,
                      P_pSharedSecret, &ss_len);

  /* destroy the CLv4 ECC context */
  cmox_ecc_cleanup(&ctx);

  /* properly set the return value */
  if (cmox_rv == CMOX_ECC_SUCCESS)
  {
    retval = C25519_SUCCESS;
  }

  return retval;
}

/* X25519 key generation function */
int32_t C25519keyGen(uint8_t *P_pPrivateKey, uint8_t *P_pPublicKey)
{
  const uint8_t base[32] = { 9u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
                             0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
                           }; /* base point */
  int32_t rv = C25519_ERR_BAD_PARAMETER; /* by default, return error */

  /* check for NULL parameters */
  if ((P_pPrivateKey != NULL) && (P_pPublicKey != NULL))
  {
    /* Clamp private key */
    P_pPrivateKey[0] &= 248u;
    P_pPrivateKey[31] &= 127u;
    P_pPrivateKey[31] |= 64u;

    /* Perform scalar multiplication to obtain the public key */
    rv = C25519keyExchange(P_pPublicKey, P_pPrivateKey, base);
  }

  return rv;
}
