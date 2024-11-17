/**
  *******************************************************************************
  * @file    legacy_v3_aes_ccm.c
  * @author  MCD Application Team
  * @brief   This file provides AES CCM functions of helper for migration
  *          of cryptographics library V3 to V4
  *******************************************************************************
  * @attention
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  *******************************************************************************
  */

#include <stdint.h>
#include "cipher/legacy_v3_aes_ccm.h"
#include "err_codes.h"

/* Initialization for AES CCM Encryption */
int32_t AES_CCM_Encrypt_Init(AESCCMctx_stt *P_pAESCCMctx, const uint8_t *P_pKey, const uint8_t *P_pNonce)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  if ((P_pAESCCMctx == NULL) || (P_pKey == NULL) || (P_pNonce == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  if ((P_pAESCCMctx->mTagSize < 4) || (P_pAESCCMctx->mTagSize > 16) || ((((uint32_t)P_pAESCCMctx->mTagSize) & 1u) == 1u)
      ||
      (P_pAESCCMctx->mNonceSize < 7) || (P_pAESCCMctx->mNonceSize > 13))
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }

  P_pAESCCMctx->cipher_handle = cmox_ccm_construct(&P_pAESCCMctx->ccm_handle, CMOX_AESFAST_CCM_ENC);
  if (P_pAESCCMctx->cipher_handle == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_cipher_init(P_pAESCCMctx->cipher_handle);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setKey(P_pAESCCMctx->cipher_handle, P_pKey, (cmox_cipher_keyLen_t)P_pAESCCMctx->mKeySize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setTagLen(P_pAESCCMctx->cipher_handle, (size_t)P_pAESCCMctx->mTagSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setPayloadLen(P_pAESCCMctx->cipher_handle, (size_t)P_pAESCCMctx->mPayloadSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setADLen(P_pAESCCMctx->cipher_handle, (size_t)P_pAESCCMctx->mAssDataSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setIV(P_pAESCCMctx->cipher_handle, P_pNonce, (size_t)P_pAESCCMctx->mNonceSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}


/* AES CCM Header processing function */
int32_t AES_CCM_Header_Append(AESCCMctx_stt *P_pAESCCMctx,
                              const uint8_t *P_pInputBuffer,
                              int32_t        P_inputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  /* Parameter Checking */
  if ((P_pAESCCMctx == NULL) || (P_pInputBuffer == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_appendAD(P_pAESCCMctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize);

  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_OPERATION;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* AES CCM Encryption function */
int32_t AES_CCM_Encrypt_Append(AESCCMctx_stt *P_pAESCCMctx,
                               const uint8_t *P_pInputBuffer,
                               int32_t        P_inputSize,
                               uint8_t       *P_pOutputBuffer,
                               int32_t       *P_pOutputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;
  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  /* Parameter Checking */
  if (P_pAESCCMctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_append(P_pAESCCMctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize,
                                   P_pOutputBuffer, &tempOutputLen);

  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_OPERATION;
    goto error;
  }

  /* Copy the cast to int32_t of tempOutputLen in order to not overwrite
     other data close to P_pOutputSize. */
  if (P_pOutputSize != NULL)
  {
    *P_pOutputSize = (int32_t)tempOutputLen;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* AES CCM Finalization during Encryption, this will create the Authentication TAG */
int32_t AES_CCM_Encrypt_Finish(AESCCMctx_stt *P_pAESCCMctx,
                               uint8_t       *P_pOutputBuffer,
                               int32_t       *P_pOutputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;
  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  /* Parameter checking */
  if ((P_pAESCCMctx == NULL) || (P_pOutputBuffer == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  if ((P_pAESCCMctx->mTagSize < 1) || (P_pAESCCMctx->mTagSize > 16))
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }

  cmox_retval = cmox_cipher_generateTag(P_pAESCCMctx->cipher_handle, P_pOutputBuffer, &tempOutputLen);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_OPERATION;
    goto error;
  }

  /* Copy the cast to int32_t of tempOutputLen in order to not overwrite
     other data close to P_pOutputSize. */
  if (P_pOutputSize != NULL)
  {
    *P_pOutputSize = (int32_t)tempOutputLen;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}


/* Initialization for AES CCM Decryption */
int32_t AES_CCM_Decrypt_Init(AESCCMctx_stt *P_pAESCCMctx, const uint8_t *P_pKey, const uint8_t *P_pNonce)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  if ((P_pAESCCMctx == NULL) || (P_pKey == NULL) || (P_pNonce == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  if ((P_pAESCCMctx->mTagSize < 4) || (P_pAESCCMctx->mTagSize > 16) || ((((uint32_t)P_pAESCCMctx->mTagSize & 1u)) == 1u)
      ||
      (P_pAESCCMctx->mNonceSize < 7) || (P_pAESCCMctx->mNonceSize > 13))
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }

  P_pAESCCMctx->cipher_handle = cmox_ccm_construct(&P_pAESCCMctx->ccm_handle, CMOX_AESFAST_CCM_DEC);
  if (P_pAESCCMctx->cipher_handle == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_cipher_init(P_pAESCCMctx->cipher_handle);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setKey(P_pAESCCMctx->cipher_handle, P_pKey, (cmox_cipher_keyLen_t)P_pAESCCMctx->mKeySize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setTagLen(P_pAESCCMctx->cipher_handle, (size_t)P_pAESCCMctx->mTagSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setPayloadLen(P_pAESCCMctx->cipher_handle, (size_t)P_pAESCCMctx->mPayloadSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setADLen(P_pAESCCMctx->cipher_handle, (size_t)P_pAESCCMctx->mAssDataSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setIV(P_pAESCCMctx->cipher_handle, P_pNonce, (size_t)P_pAESCCMctx->mNonceSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* AES CCM Decryption function */
int32_t AES_CCM_Decrypt_Append(AESCCMctx_stt *P_pAESCCMctx,
                               const uint8_t *P_pInputBuffer,
                               int32_t        P_inputSize,
                               uint8_t       *P_pOutputBuffer,
                               int32_t       *P_pOutputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;
  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  /* Parameter Checking */
  if (P_pAESCCMctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_append(P_pAESCCMctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize,
                                   P_pOutputBuffer, &tempOutputLen);

  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_OPERATION;
    goto error;
  }

  /* Copy the cast to int32_t of tempOutputLen in order to not overwrite
     other data close to P_pOutputSize. */
  if (P_pOutputSize != NULL)
  {
    *P_pOutputSize = (int32_t)tempOutputLen;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* AES CCM Finalization during Decryption, the authentication TAG will be checked */
int32_t AES_CCM_Decrypt_Finish(AESCCMctx_stt *P_pAESCCMctx,
                               uint8_t       *P_pOutputBuffer,
                               int32_t       *P_pOutputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  (void)P_pOutputBuffer;

  /* Parameter checking */
  if (P_pAESCCMctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  if ((P_pAESCCMctx->mTagSize < 1) || (P_pAESCCMctx->mTagSize > 16))
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }
  if (P_pAESCCMctx->pmTag == NULL)
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }

  if (P_pOutputSize != NULL)
  {
    *P_pOutputSize = 0;
  }

  cmox_retval = cmox_cipher_verifyTag(P_pAESCCMctx->cipher_handle, P_pAESCCMctx->pmTag, NULL);
  if (cmox_retval == CMOX_CIPHER_AUTH_SUCCESS)
  {
    retval = AUTHENTICATION_SUCCESSFUL;
  }
  else if (cmox_retval == CMOX_CIPHER_AUTH_FAIL)
  {
    retval = AUTHENTICATION_FAILED;
  }
  else
  {
    retval = AES_ERR_BAD_OPERATION;
  }

error:
  return retval;
}
