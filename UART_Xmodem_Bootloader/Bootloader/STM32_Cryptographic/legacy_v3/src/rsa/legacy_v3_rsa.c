/**
  ******************************************************************************
  * @file    legacy_v3_rsa.c
  * @author  MCD Application Team
  * @brief   This file provides RSA PKCS#1 v1.5 functions of helper for
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

#include "membuf/legacy_v3_membuf_internal.h"
#include "rsa/legacy_v3_rsa.h"
#include "rsa/cmox_rsa_pkcs1v15.h"
#include "drbg/legacy_v3_ctr_drbg.h"
#include "err_codes.h"
#include <string.h>

/* Private API */

/**
  * @brief Convert CLV4 results into CLv3 results
  * @param[in]  cmox_rv  Result of a CLv4 API
  * @return CLv3 rturn value correspondent to the input one
  */
static int32_t cmox_helper_rsa_rv_convert(cmox_rsa_retval_t cmox_rv)
{
  int32_t rv;

  switch (cmox_rv)
  {
    case CMOX_RSA_SUCCESS: /* everything ok */
      rv = RSA_SUCCESS;
      break;
    case CMOX_RSA_AUTH_SUCCESS: /* verification pass */
      rv = SIGNATURE_VALID;
      break;
    case CMOX_RSA_AUTH_FAIL: /* verification fail */
    case CMOX_RSA_ERR_INVALID_SIGNATURE: /* invalid/bad formatted signature */
      rv = SIGNATURE_INVALID;
      break;
    case CMOX_RSA_ERR_MODULUS_TOO_SHORT: /* modulus too short */
      rv = RSA_ERR_MODULUS_TOO_SHORT;
      break;
    case CMOX_RSA_ERR_WRONG_DECRYPTION: /* Error in decryption */
      rv = RSA_ERR_GENERIC;
      break;
    case CMOX_RSA_ERR_MEMORY_FAIL: /* not enough memory */
      rv = ERR_MEMORY_FAIL;
      break;
    default: /* CMOX_RSA_ERR_BAD_PARAMETERS */
      rv = RSA_ERR_BAD_PARAMETER;
      break;
  }

  return rv;
}

/**
  * @brief Maps CLv3 hash codes to CLv4 RSA hash codes
  */
static cmox_rsa_pkcs1v15_hash_t rsa_hash_map(hashType_et P_hashType)
{
  cmox_rsa_pkcs1v15_hash_t rv = NULL;

  switch (P_hashType)
  {
    case E_SHA1:
      rv = CMOX_RSA_PKCS1V15_HASH_SHA1;
      break;
    case E_SHA224:
      rv = CMOX_RSA_PKCS1V15_HASH_SHA224;
      break;
    case E_SHA256:
      rv = CMOX_RSA_PKCS1V15_HASH_SHA256;
      break;
    case E_SHA384:
      rv = CMOX_RSA_PKCS1V15_HASH_SHA384;
      break;
    case E_SHA512:
      rv = CMOX_RSA_PKCS1V15_HASH_SHA512;
      break;
    default:
      break;
  }

  return rv;
}

/* Public API */

int32_t RSA_PKCS1v15_Sign(const RSAprivKey_stt *P_pPrivKey,
                          const uint8_t        *P_pDigest,
                          hashType_et          P_hashType,
                          uint8_t              *P_pSignature,
                          membuf_stt           *P_pMemBuf)
{
  cmox_rsa_retval_t cmox_rv; /* CLv4 return value */
  int32_t retval; /* return value */
  cmox_rsa_handle_t ctx; /* RSA context */
  cmox_rsa_key_t key; /* key structure */
  cmox_rsa_pkcs1v15_hash_t hash; /* hash used in the PKCS padding */

  /* check the hash */
  hash = rsa_hash_map(P_hashType);
  if (hash == NULL)
  {
    retval = RSA_ERR_UNSUPPORTED_HASH;
  }
  else
  {
    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_rsa_construct(&ctx, CMOX_MATH_FUNCS_SMALL, CMOX_MODEXP_PRIVATE,
                       &(P_pMemBuf->pmBuf[P_pMemBuf->mUsed]), (size_t)P_pMemBuf->mSize - (size_t)P_pMemBuf->mUsed);

    /* set the private key */
    cmox_rv = cmox_rsa_setKey(&key,
                              P_pPrivKey->pmModulus, (size_t)P_pPrivKey->mModulusSize,
                              P_pPrivKey->pmExponent, (size_t)P_pPrivKey->mExponentSize);
    if (cmox_rv != CMOX_RSA_SUCCESS)
    {
      retval = RSA_ERR_BAD_KEY;
    }
    else
    {
      /* perform RSA signing with CLv4 */
      cmox_rv = cmox_rsa_pkcs1v15_sign(&ctx, &key, P_pDigest, hash, P_pSignature, NULL);
      /* properly set the return value */
      retval = cmox_helper_rsa_rv_convert(cmox_rv);
    }

    /* destroy the context */
    cmox_rsa_cleanup(&ctx);
  }

  return retval;
}

int32_t RSA_PKCS1v15_Verify(const RSApubKey_stt *P_pPubKey,
                            const uint8_t       *P_pDigest,
                            hashType_et         P_hashType,
                            const uint8_t       *P_pSignature,
                            membuf_stt          *P_pMemBuf)
{
  cmox_rsa_retval_t cmox_rv; /* CLv4 return value */
  int32_t retval; /* return value */
  cmox_rsa_handle_t ctx; /* RSA context */
  cmox_rsa_key_t key; /* key structure */
  cmox_rsa_pkcs1v15_hash_t hash; /* hash used in the PKCS padding */

  /* check the hash */
  hash = rsa_hash_map(P_hashType);
  if (hash == NULL)
  {
    retval = RSA_ERR_UNSUPPORTED_HASH;
  }
  else
  {
    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_rsa_construct(&ctx, CMOX_MATH_FUNCS_SMALL, CMOX_MODEXP_PUBLIC,
                       &(P_pMemBuf->pmBuf[P_pMemBuf->mUsed]), (size_t)P_pMemBuf->mSize - (size_t)P_pMemBuf->mUsed);

    /* set the public key */
    cmox_rv = cmox_rsa_setKey(&key,
                              P_pPubKey->pmModulus, (size_t)P_pPubKey->mModulusSize,
                              P_pPubKey->pmExponent, (size_t)P_pPubKey->mExponentSize);
    if (cmox_rv != CMOX_RSA_SUCCESS)
    {
      retval = RSA_ERR_BAD_KEY;
    }
    else
    {
      /* perform RSA verification with CLv4 */
      cmox_rv = cmox_rsa_pkcs1v15_verify(&ctx, &key,
                                         P_pDigest, rsa_hash_map(P_hashType),
                                         P_pSignature, (size_t)P_pPubKey->mModulusSize,
                                         NULL);
      /* properly set the return value */
      retval = cmox_helper_rsa_rv_convert(cmox_rv);
    }

    /* destroy the context */
    cmox_rsa_cleanup(&ctx);
  }

  return retval;
}

int32_t RSA_PKCS1v15_Encrypt(const RSApubKey_stt *P_pPubKey,
                             RSAinOut_stt        *P_pInOut_st,
                             RNGstate_stt        *P_pRandomState,
                             membuf_stt          *P_pMemBuf)
{
  cmox_rsa_retval_t cmox_rv; /* CLv4 return value */
  int32_t retval; /* return value */
  cmox_rsa_handle_t ctx; /* RSA context */
  cmox_rsa_key_t key; /* key structure */
  uint8_t *random;

  /* allocate memory for the random buffer to generate */
  cmox_rv = clv3_allocate(P_pMemBuf, &random, (uint16_t)P_pPubKey->mModulusSize);
  if (cmox_rv != 0u)
  {
    retval = ERR_MEMORY_FAIL;
  }
  else
  {
    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_rsa_construct(&ctx, CMOX_MATH_FUNCS_SMALL, CMOX_MODEXP_PUBLIC,
                       &(P_pMemBuf->pmBuf[P_pMemBuf->mUsed]), (size_t)P_pMemBuf->mSize - (size_t)P_pMemBuf->mUsed);

    /* set the public key */
    cmox_rv = cmox_rsa_setKey(&key,
                              P_pPubKey->pmModulus, (size_t)P_pPubKey->mModulusSize,
                              P_pPubKey->pmExponent, (size_t)P_pPubKey->mExponentSize);
    if (cmox_rv != CMOX_RSA_SUCCESS)
    {
      retval = RSA_ERR_BAD_KEY;
    }
    else
    {
      /* generate random until it's valid for RSA encryption function */
      do
      {
        /* generate a random number of the same BYTElength of N */
        retval = RNGgenBytes(P_pRandomState, NULL, random, P_pPubKey->mModulusSize);
        if (retval != 0)
        {
          cmox_rv = CMOX_RSA_ERR_BAD_PARAMETER;
        }
        else
        {
          /* perform RSA encryption with CLv4 */
          cmox_rv = cmox_rsa_pkcs1v15_encrypt(&ctx, &key,
                                              P_pInOut_st->pmInput, (size_t)P_pInOut_st->mInputSize,
                                              random, (size_t)P_pPubKey->mModulusSize,
                                              P_pInOut_st->pmOutput, NULL);
        }
      } while (cmox_rv == CMOX_RSA_ERR_WRONG_RANDOM);

      /* properly set the return value */
      retval = cmox_helper_rsa_rv_convert(cmox_rv);
    }

    /* destroy the context */
    cmox_rsa_cleanup(&ctx);

    /* free the random buffer */
    (void)clv3_free(P_pMemBuf, &random, (uint16_t)P_pPubKey->mModulusSize);
  }

  return retval;
}

int32_t RSA_PKCS1v15_Decrypt(const RSAprivKey_stt *P_pPrivKey,
                             RSAinOut_stt         *P_pInOut_st,
                             int32_t              *P_pOutputSize,
                             membuf_stt           *P_pMemBuf)
{
  cmox_rsa_retval_t cmox_rv; /* CLv4 return value */
  int32_t retval; /* return value */
  cmox_rsa_handle_t ctx; /* RSA context */
  cmox_rsa_key_t key; /* key structure */
  size_t out_size;

  /* synchronize CLv3 membuf to CLv4 membuf */
  cmox_rsa_construct(&ctx, CMOX_MATH_FUNCS_SMALL, CMOX_MODEXP_PRIVATE,
                     &(P_pMemBuf->pmBuf[P_pMemBuf->mUsed]), (size_t)P_pMemBuf->mSize - (size_t)P_pMemBuf->mUsed);

  /* set the private key */
  cmox_rv = cmox_rsa_setKey(&key,
                            P_pPrivKey->pmModulus, (size_t)P_pPrivKey->mModulusSize,
                            P_pPrivKey->pmExponent, (size_t)P_pPrivKey->mExponentSize);
  if (cmox_rv != CMOX_RSA_SUCCESS)
  {
    retval = RSA_ERR_BAD_KEY;
  }
  else
  {
    /* perform RSA decryption with CLv4 */
    cmox_rv = cmox_rsa_pkcs1v15_decrypt(&ctx, &key,
                                        P_pInOut_st->pmInput, (size_t)P_pInOut_st->mInputSize,
                                        P_pInOut_st->pmOutput, &out_size);
    if (cmox_rv == CMOX_RSA_SUCCESS)
    {
      *P_pOutputSize = (int32_t)out_size;
    }
    /* properly set the return value */
    retval = cmox_helper_rsa_rv_convert(cmox_rv);
  }

  /* destroy the context */
  cmox_rsa_cleanup(&ctx);

  return retval;
}
