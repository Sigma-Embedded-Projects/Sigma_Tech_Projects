/**
  *******************************************************************************
  * @file    legacy_v3_aes_keywrap.c
  * @author  MCD Application Team
  * @brief   This file provides AES KeyWrap functions of helper for migration
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

#include "cipher/legacy_v3_aes_keywrap.h"
#include "cipher/legacy_v3_aes.h"
#include "cipher/cmox_keywrap.h"
#include "err_codes.h"

/* Initialization for AES Encryption in KeyWrap Mode */
int32_t AES_KeyWrap_Encrypt_Init(AESKeyWrapctx_stt *P_pAESKeyWrapctx, const uint8_t *P_pKey, const uint8_t *P_pIv)
{
  cmox_cipher_retval_t cmox_retval;
  int32_t retval;

  if (P_pAESKeyWrapctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  P_pAESKeyWrapctx->cipher_handle = cmox_keywrap_construct(&P_pAESKeyWrapctx->keywrap_handle, CMOX_AESFAST_KEYWRAP_ENC);
  if (P_pAESKeyWrapctx->cipher_handle == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_cipher_init(P_pAESKeyWrapctx->cipher_handle);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setKey(P_pAESKeyWrapctx->cipher_handle, P_pKey, (size_t)P_pAESKeyWrapctx->mKeySize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setIV(P_pAESKeyWrapctx->cipher_handle, P_pIv, (size_t)P_pAESKeyWrapctx->mIvSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* AES Encryption in KeyWrap Mode */
int32_t AES_KeyWrap_Encrypt_Append(AESKeyWrapctx_stt *P_pAESKeyWrapctx,
                                   const uint8_t *P_pInputBuffer,
                                   int32_t        P_inputSize,
                                   uint8_t       *P_pOutputBuffer,
                                   int32_t       *P_pOutputSize)
{
  cmox_cipher_retval_t cmox_retval;
  int32_t retval;
  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  if (P_pAESKeyWrapctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  if (P_inputSize < 16)
  {
    retval = AES_ERR_BAD_INPUT_SIZE;
    goto error;
  }

  cmox_retval = cmox_cipher_append(P_pAESKeyWrapctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize,
                                   P_pOutputBuffer, &tempOutputLen);
  if (cmox_retval == CMOX_CIPHER_ERR_BAD_OPERATION)
  {
    retval = AES_ERR_BAD_OPERATION;
    goto error;
  }

  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
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

/* AES Encryption Finalization of KeyWrap Mode */
int32_t AES_KeyWrap_Encrypt_Finish(AESKeyWrapctx_stt *P_pAESKeyWrapctx,
                                   uint8_t       *P_pOutputBuffer,
                                   int32_t       *P_pOutputSize)
{
  (void)P_pOutputBuffer;
  int32_t retval;
  /* Parameter checking */
  if ((P_pAESKeyWrapctx == NULL) || (P_pOutputSize == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  P_pAESKeyWrapctx->mFlags |= E_SK_OPERATION_COMPLETED;
  *P_pOutputSize = 0;
  retval = AES_SUCCESS;

error:
  return retval;
}

/* Initialization for AES Decryption in KeyWrap Mode */
int32_t AES_KeyWrap_Decrypt_Init(AESKeyWrapctx_stt *P_pAESKeyWrapctx, const uint8_t *P_pKey, const uint8_t *P_pIv)
{
  cmox_cipher_retval_t cmox_retval;
  int32_t retval;

  if (P_pAESKeyWrapctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  P_pAESKeyWrapctx->cipher_handle = cmox_keywrap_construct(&P_pAESKeyWrapctx->keywrap_handle, CMOX_AESFAST_KEYWRAP_DEC);
  if (P_pAESKeyWrapctx->cipher_handle == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_cipher_init(P_pAESKeyWrapctx->cipher_handle);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setKey(P_pAESKeyWrapctx->cipher_handle, P_pKey, (size_t)P_pAESKeyWrapctx->mKeySize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setIV(P_pAESKeyWrapctx->cipher_handle, P_pIv, (size_t)P_pAESKeyWrapctx->mIvSize);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* AES Decryption in KeyWrap Mode */
int32_t AES_KeyWrap_Decrypt_Append(AESKeyWrapctx_stt *P_pAESKeyWrapctx,
                                   const uint8_t *P_pInputBuffer,
                                   int32_t        P_inputSize,
                                   uint8_t       *P_pOutputBuffer,
                                   int32_t       *P_pOutputSize)
{
  cmox_cipher_retval_t cmox_retval;
  int32_t retval;

  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  if (P_pAESKeyWrapctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  if (P_inputSize < 16)
  {
    retval = AES_ERR_BAD_INPUT_SIZE;
    goto error;
  }

  cmox_retval = cmox_cipher_append(P_pAESKeyWrapctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize,
                                   P_pOutputBuffer, &tempOutputLen);
  if (cmox_retval == CMOX_CIPHER_ERR_BAD_OPERATION)
  {
    retval = AES_ERR_BAD_OPERATION;
    goto error;
  }

  if (cmox_retval != CMOX_CIPHER_AUTH_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
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

/* AES Decryption Finalization of KeyWrap Mode */
int32_t AES_KeyWrap_Decrypt_Finish(AESKeyWrapctx_stt *P_pAESKeyWrapctx,
                                   uint8_t       *P_pOutputBuffer,
                                   int32_t       *P_pOutputSize)
{
  (void)P_pOutputBuffer;
  int32_t retval;
  /* Parameter checking */
  if ((P_pAESKeyWrapctx == NULL) || (P_pOutputSize == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  P_pAESKeyWrapctx->mFlags |= E_SK_OPERATION_COMPLETED;
  *P_pOutputSize = 0;
  retval = AUTHENTICATION_SUCCESSFUL;

error:
  return retval;
}
