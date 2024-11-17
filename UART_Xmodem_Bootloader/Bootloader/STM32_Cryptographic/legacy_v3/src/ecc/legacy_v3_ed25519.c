/**
  ******************************************************************************
  * @file    legacy_v3_ed25519.c
  * @author  MCD Application Team
  * @brief   This file provides ED25519 functions of helper for
  *          migration of cryptographics library V3 to V4
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

#include "ecc/cmox_eddsa.h"
#include "err_codes.h"
#include "ecc/legacy_v3_ed25519.h"

/* internal function to convert CLV4 results into CLv3 results */
static int32_t cmox_helper_ed25519_rv_convert(cmox_ecc_retval_t cmox_rv)
{
  int32_t rv;

  switch (cmox_rv)
  {
    case CMOX_ECC_SUCCESS:
      rv = ED25519_SUCCESS; /* result OK */
      break;
    case CMOX_ECC_ERR_INVALID_PUBKEY:
      rv = ED25519_ERR_BAD_POINT; /* provided public key is wrong */
      break;
    case CMOX_ECC_ERR_INTERNAL:
      rv = HASH_ERR_INTERNAL; /* error in hashing with sha512 */
      break;
    default:
      rv = ED25519_ERR_BAD_PARAMETER; /* default error value */
      break;
  }

  return rv;
}

/* ED25519 key generation function */
int32_t ED25519keyGen(uint8_t *P_pPrivateKey, uint8_t *P_pPublicKey)
{
  cmox_ecc_handle_t ctx; /* CLv4 internal ECC context */
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */
  uint8_t buf[544 + 52]; /* CLv4 internal memory buffer */
  int32_t retval;
  size_t pk_len, sk_len;

  /* set the internal memory buffer and the default math engine */
  cmox_ecc_construct(&ctx, CMOX_ECC256_MATH_FUNCS, buf, sizeof(buf));

  /* perform key generation with CLv4 */
  cmox_rv = cmox_eddsa_keyGen(&ctx, CMOX_ECC_ED25519_OPT_LOWMEM,
                              P_pPrivateKey, 32u,
                              P_pPrivateKey, &sk_len,
                              P_pPublicKey, &pk_len);

  /* destroy the CLv4 ECC context */
  cmox_ecc_cleanup(&ctx);

  /* properly set the return value */
  retval = cmox_helper_ed25519_rv_convert(cmox_rv);

  return retval;
}

/* ED25519 signing function */
int32_t ED25519sign(uint8_t       *P_pSignature,
                    const uint8_t *P_pInput,
                    int32_t       P_InputSize,
                    const uint8_t *P_pPrivateKey)
{
  cmox_ecc_handle_t ctx; /* CLv4 internal ECC context */
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */
  uint8_t buf[644 + 52]; /* CLv4 internal memory buffer */
  int32_t retval;
  size_t sig_len;

  /* set the internal memory buffer and the default math engine */
  cmox_ecc_construct(&ctx, CMOX_ECC256_MATH_FUNCS, buf, sizeof(buf));

  /* perform signature generation with CLv4 */
  cmox_rv = cmox_eddsa_sign(&ctx, CMOX_ECC_ED25519_OPT_LOWMEM,
                            P_pPrivateKey, 64u,
                            P_pInput, (size_t)P_InputSize,
                            P_pSignature, &sig_len);

  /* destroy the CLv4 ECC context */
  cmox_ecc_cleanup(&ctx);

  /* properly set the return value */
  retval = cmox_helper_ed25519_rv_convert(cmox_rv);

  return retval;
}

/* ED25519 verification function */
int32_t ED25519verify(const uint8_t *P_pInput,
                      int32_t       P_InputSize,
                      const uint8_t *P_pSignature,
                      const uint8_t *P_pPublicKey)
{
  cmox_ecc_handle_t ctx; /* CLv4 internal ECC context */
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */
  uint8_t buf[984 + 96]; /* CLv4 internal memory buffer */
  int32_t retval = SIGNATURE_INVALID;

  /* set the internal memory buffer and the default math engine */
  cmox_ecc_construct(&ctx, CMOX_ECC256_MATH_FUNCS, buf, sizeof(buf));

  /* perform signature verification with CLv4 */
  cmox_rv = cmox_eddsa_verify(&ctx, CMOX_ECC_ED25519_OPT_LOWMEM,
                              P_pPublicKey, 32u,
                              P_pInput, (size_t)P_InputSize,
                              P_pSignature, 64u,
                              NULL);

  /* destroy the CLv4 ECC context */
  cmox_ecc_cleanup(&ctx);

  /* properly set the return value */
  if (cmox_rv == CMOX_ECC_AUTH_SUCCESS)
  {
    retval = SIGNATURE_VALID;
  }

  return retval;
}
