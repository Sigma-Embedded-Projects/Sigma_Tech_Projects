/**
  *******************************************************************************
  * @file    legacy_v3_aes_gcm.c
  * @author  MCD Application Team
  * @brief   This file provides AES GCM functions of helper for migration
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
#include "cipher/legacy_v3_aes_gcm.h"
#include "err_codes.h"

/* Initialization for AES GCM Encryption */
int32_t AES_GCM_Encrypt_Init(AESGCMctx_stt *P_pAESGCMctx, const uint8_t *P_pKey, const uint8_t *P_pIv)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  if ((P_pAESGCMctx == NULL) || (P_pKey == NULL) || (P_pIv == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  if ((P_pAESGCMctx->mTagSize < 1) || (P_pAESGCMctx->mTagSize > 16) ||
      (P_pAESGCMctx->mIvSize != 12) ||
      ((P_pAESGCMctx->mKeySize != CRL_AES128_KEY) && (P_pAESGCMctx->mKeySize != CRL_AES192_KEY)
       && (P_pAESGCMctx->mKeySize != CRL_AES256_KEY)))
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }

  P_pAESGCMctx->cipher_handle = cmox_gcmFast_construct(&P_pAESGCMctx->gcm_handle, CMOX_AESFAST_GCMFAST_ENC);
  if (P_pAESGCMctx->cipher_handle == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_cipher_init(P_pAESGCMctx->cipher_handle);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setKey(P_pAESGCMctx->cipher_handle, P_pKey, (cmox_cipher_keyLen_t)P_pAESGCMctx->mKeySize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setTagLen(P_pAESGCMctx->cipher_handle, (size_t)P_pAESGCMctx->mTagSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setIV(P_pAESGCMctx->cipher_handle, P_pIv, (size_t)P_pAESGCMctx->mIvSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}


/* AES GCM Header processing function */
int32_t AES_GCM_Header_Append(AESGCMctx_stt *P_pAESGCMctx,
                              const uint8_t *P_pInputBuffer,
                              int32_t        P_inputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  /* Parameter Checking */
  if ((P_pAESGCMctx == NULL) || (P_pInputBuffer == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_appendAD(P_pAESGCMctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize);

  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_OPERATION;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* AES GCM Encryption function */
int32_t AES_GCM_Encrypt_Append(AESGCMctx_stt *P_pAESGCMctx,
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
  if (P_pAESGCMctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_append(P_pAESGCMctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize,
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

/* AES GCM Finalization during Encryption, this will create the Authentication TAG */
int32_t AES_GCM_Encrypt_Finish(AESGCMctx_stt *P_pAESGCMctx,
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
  if ((P_pAESGCMctx == NULL) || (P_pOutputBuffer == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  if ((P_pAESGCMctx->mTagSize < 1) || (P_pAESGCMctx->mTagSize > 16))
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }

  cmox_retval = cmox_cipher_generateTag(P_pAESGCMctx->cipher_handle, P_pOutputBuffer, &tempOutputLen);
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


/* Initialization for AES GCM Decryption */
int32_t AES_GCM_Decrypt_Init(AESGCMctx_stt *P_pAESGCMctx, const uint8_t *P_pKey, const uint8_t *P_pIv)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  if ((P_pAESGCMctx == NULL) || (P_pKey == NULL) || (P_pIv == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  if ((P_pAESGCMctx->mTagSize < 1) || (P_pAESGCMctx->mTagSize > 16) ||
      (P_pAESGCMctx->mIvSize != 12) ||
      ((P_pAESGCMctx->mKeySize != CRL_AES128_KEY) && (P_pAESGCMctx->mKeySize != CRL_AES192_KEY)
       && (P_pAESGCMctx->mKeySize != CRL_AES256_KEY)))
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }
  /* We are initializing, so let's set to zero some finalization flags */
  P_pAESGCMctx->mFlags &= ~(E_SK_NO_MORE_APPEND_ALLOWED
                            | E_SK_OPERATION_COMPLETED | E_SK_NO_MORE_HEADER_APPEND_ALLOWED);

  P_pAESGCMctx->cipher_handle = cmox_gcmFast_construct(&P_pAESGCMctx->gcm_handle, CMOX_AESFAST_GCMFAST_DEC);
  if (P_pAESGCMctx->cipher_handle == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_cipher_init(P_pAESGCMctx->cipher_handle);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setKey(P_pAESGCMctx->cipher_handle, P_pKey, (cmox_cipher_keyLen_t)P_pAESGCMctx->mKeySize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setTagLen(P_pAESGCMctx->cipher_handle, (size_t)P_pAESGCMctx->mTagSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setIV(P_pAESGCMctx->cipher_handle, P_pIv, (size_t)P_pAESGCMctx->mIvSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* AES GCM Decryption function */
int32_t AES_GCM_Decrypt_Append(AESGCMctx_stt *P_pAESGCMctx,
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
  if (P_pAESGCMctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_append(P_pAESGCMctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize,
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



/* AES GCM Finalization during Decryption, the authentication TAG will be checked */
int32_t AES_GCM_Decrypt_Finish(AESGCMctx_stt *P_pAESGCMctx,
                               uint8_t       *P_pOutputBuffer,
                               int32_t       *P_pOutputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  (void)P_pOutputBuffer;

  /* Parameter checking */
  if (P_pAESGCMctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  if ((P_pAESGCMctx->mTagSize < 1) || (P_pAESGCMctx->mTagSize > 16))
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }
  if (P_pAESGCMctx->pmTag == NULL)
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }

  if (P_pOutputSize != NULL)
  {
    *P_pOutputSize = 0;
  }

  cmox_retval = cmox_cipher_verifyTag(P_pAESGCMctx->cipher_handle, P_pAESGCMctx->pmTag, NULL);
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
