/**
  *******************************************************************************
  * @file    legacy_v3_chachapoly.c
  * @author  MCD Application Team
  * @brief   This file provides ChaCha20-Poly1305 functions of helper for
  *          migration of cryptographics library V3 to V4
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
#include "cipher/legacy_v3_chachapoly.h"
#include "err_codes.h"

/* Initialization for ChaCha20-Poly1305 AEAD Encryption Algorithm */
int32_t ChaCha20Poly1305_Encrypt_Init(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                      const uint8_t *P_pKey,
                                      const uint8_t *P_pNonce)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  if ((P_pChaCha20Poly1305ctx == NULL) || (P_pKey == NULL) || (P_pNonce == NULL))
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }

  P_pChaCha20Poly1305ctx->cipher_handle = cmox_chachapoly_construct(&P_pChaCha20Poly1305ctx->chachapoly_handle,
                                                                    CMOX_CHACHAPOLY_ENC);
  if (P_pChaCha20Poly1305ctx->cipher_handle == NULL)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_cipher_init(P_pChaCha20Poly1305ctx->cipher_handle);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setKey(P_pChaCha20Poly1305ctx->cipher_handle, P_pKey, 32u);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setTagLen(P_pChaCha20Poly1305ctx->cipher_handle, 16u);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setIV(P_pChaCha20Poly1305ctx->cipher_handle, P_pNonce, 12u);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = CHACHA20POLY1305_SUCCESS;

error:
  return retval;
}

/* ChaCha20-Poly1305 AAD (Additional Authenticated Data) processing function */
int32_t ChaCha20Poly1305_Header_Append(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                       const uint8_t *P_pInputBuffer,
                                       int32_t P_inputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  /* Parameter Checking */
  if ((P_pChaCha20Poly1305ctx == NULL) || (P_pInputBuffer == NULL))
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_appendAD(P_pChaCha20Poly1305ctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize);

  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_OPERATION;
    goto error;
  }

  retval = CHACHA20POLY1305_SUCCESS;

error:
  return retval;
}

/* ChaCha20-Poly1305 AEAD Encryption processing function */
int32_t ChaCha20Poly1305_Encrypt_Append(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                        const uint8_t *P_pInputBuffer,
                                        int32_t P_inputSize,
                                        uint8_t *P_pOutputBuffer,
                                        int32_t *P_pOutputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;
  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  /* Parameter Checking */
  if (P_pChaCha20Poly1305ctx == NULL)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_append(P_pChaCha20Poly1305ctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize,
                                   P_pOutputBuffer, &tempOutputLen);

  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_OPERATION;
    goto error;
  }

  /* Copy the cast to int32_t of tempOutputLen in order to not overwrite
     other data close to P_pOutputSize. */
  if (P_pOutputSize != NULL)
  {
    *P_pOutputSize = (int32_t)tempOutputLen;
  }

  retval = CHACHA20POLY1305_SUCCESS;

error:
  return retval;
}

/* ChaCha20-Poly1305 TAG generation function */
int32_t ChaCha20Poly1305_Encrypt_Finish(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                        uint8_t *P_pOutputBuffer,
                                        int32_t *P_pOutputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;
  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  /* Parameter checking */
  if ((P_pChaCha20Poly1305ctx == NULL) || (P_pOutputBuffer == NULL))
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_cipher_generateTag(P_pChaCha20Poly1305ctx->cipher_handle, P_pOutputBuffer, &tempOutputLen);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_OPERATION;
    goto error;
  }

  /* Copy the cast to int32_t of tempOutputLen in order to not overwrite
     other data close to P_pOutputSize. */
  if (P_pOutputSize != NULL)
  {
    *P_pOutputSize = (int32_t)tempOutputLen;
  }

  retval = CHACHA20POLY1305_SUCCESS;

error:
  return retval;
}

/* Initialization for ChaCha20-Poly1305 AEAD Decryption Algorithm */
int32_t ChaCha20Poly1305_Decrypt_Init(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                      const uint8_t *P_pKey,
                                      const uint8_t *P_pNonce)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  if ((P_pChaCha20Poly1305ctx == NULL) || (P_pKey == NULL) || (P_pNonce == NULL))
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }

  P_pChaCha20Poly1305ctx->cipher_handle = cmox_chachapoly_construct(&P_pChaCha20Poly1305ctx->chachapoly_handle,
                                                                    CMOX_CHACHAPOLY_DEC);
  if (P_pChaCha20Poly1305ctx->cipher_handle == NULL)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_cipher_init(P_pChaCha20Poly1305ctx->cipher_handle);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setKey(P_pChaCha20Poly1305ctx->cipher_handle, P_pKey, 32u);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setTagLen(P_pChaCha20Poly1305ctx->cipher_handle, 16u);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_setIV(P_pChaCha20Poly1305ctx->cipher_handle, P_pNonce, 12u);
  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = CHACHA20POLY1305_SUCCESS;

error:
  return retval;
}

/* ChaCha20-Poly1305 AEAD Decryption processing function */
int32_t ChaCha20Poly1305_Decrypt_Append(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                        const uint8_t *P_pInputBuffer,
                                        int32_t P_inputSize,
                                        uint8_t *P_pOutputBuffer,
                                        int32_t *P_pOutputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;
  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  /* Parameter Checking */
  if (P_pChaCha20Poly1305ctx == NULL)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_cipher_append(P_pChaCha20Poly1305ctx->cipher_handle, P_pInputBuffer, (size_t)P_inputSize,
                                   P_pOutputBuffer, &tempOutputLen);

  if (cmox_retval != CMOX_CIPHER_SUCCESS)
  {
    retval = CHACHA20POLY1305_ERR_BAD_OPERATION;
    goto error;
  }

  /* Copy the cast to int32_t of tempOutputLen in order to not overwrite
     other data close to P_pOutputSize. */
  if (P_pOutputSize != NULL)
  {
    *P_pOutputSize = (int32_t)tempOutputLen;
  }

  retval = CHACHA20POLY1305_SUCCESS;

error:
  return retval;
}

/* ChaCha20-Poly1305 Authentication TAG verification function */
int32_t ChaCha20Poly1305_Decrypt_Finish(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                        uint8_t *P_pOutputBuffer,
                                        int32_t *P_pOutputSize)
{
  int32_t retval;
  cmox_cipher_retval_t cmox_retval;

  (void)P_pOutputBuffer;

  /* Parameter checking */
  if (P_pChaCha20Poly1305ctx == NULL)
  {
    retval = CHACHA20POLY1305_ERR_BAD_PARAMETER;
    goto error;
  }
  if (P_pChaCha20Poly1305ctx->pmTag == NULL)
  {
    retval = CHACHA20POLY1305_ERR_BAD_CONTEXT;
    goto error;
  }

  if (P_pOutputSize != NULL)
  {
    *P_pOutputSize = 0;
  }

  cmox_retval = cmox_cipher_verifyTag(P_pChaCha20Poly1305ctx->cipher_handle, P_pChaCha20Poly1305ctx->pmTag, NULL);
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
    retval = CHACHA20POLY1305_ERR_BAD_OPERATION;
  }

error:
  return retval;
}
