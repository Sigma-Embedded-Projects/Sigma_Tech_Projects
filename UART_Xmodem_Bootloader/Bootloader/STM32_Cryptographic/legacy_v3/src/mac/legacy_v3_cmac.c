/**
  *******************************************************************************
  * @file    legacy_v3_cmac.c
  * @author  MCD Application Team
  * @brief   This file provides CMAC functions of helper for
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

#include "mac/legacy_v3_cmac.h"
#include "err_codes.h"

/* Initialization for AES-CMAC for Authentication TAG Generation */
int32_t AES_CMAC_Encrypt_Init(AESCMACctx_stt *P_pAESCMACctx)
{
  cmox_mac_retval_t cmox_retval;
  int32_t retval;

  /* Parameter Checking */
  if (P_pAESCMACctx == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  P_pAESCMACctx->mac_handle = cmox_cmac_construct(&P_pAESCMACctx->cmac_handle, CMOX_CMAC_AESFAST);
  if (P_pAESCMACctx->mac_handle == NULL)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_mac_init(P_pAESCMACctx->mac_handle);
  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_mac_setTagLen(P_pAESCMACctx->mac_handle, (size_t)P_pAESCMACctx->mTagSize);
  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }

  cmox_retval = cmox_mac_setKey(P_pAESCMACctx->mac_handle, P_pAESCMACctx->pmKey, (size_t)P_pAESCMACctx->mKeySize);
  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = AES_ERR_BAD_CONTEXT;
    goto error;
  }

  retval = AES_SUCCESS;
error:
  return retval;
}

/* AES Encryption in CMAC Mode */
int32_t AES_CMAC_Encrypt_Append(AESCMACctx_stt *P_pAESCMACctx,
                                const uint8_t *P_pInputBuffer,
                                int32_t        P_inputSize)
{
  cmox_mac_retval_t cmox_retval;
  int32_t retval;

  if ((P_pAESCMACctx == NULL) || (P_inputSize < 0))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  /* If there is no plaintext, exit without doing nothing */
  if ((P_pInputBuffer == NULL) || (P_inputSize == 0))
  {
    retval = AES_SUCCESS;
    goto error;
  }

  cmox_retval = cmox_mac_append(P_pAESCMACctx->mac_handle, P_pInputBuffer, (size_t)P_inputSize);

  if (cmox_retval == CMOX_MAC_ERR_BAD_OPERATION)
  {
    retval = AES_ERR_BAD_OPERATION;
    goto error;
  }

  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* AES Finalization of CMAC Mode */
int32_t AES_CMAC_Encrypt_Finish(AESCMACctx_stt *P_pAESCMACctx,
                                uint8_t       *P_pOutputBuffer,
                                int32_t       *P_pOutputSize)
{
  cmox_mac_retval_t cmox_retval;
  int32_t retval;
  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  if ((P_pAESCMACctx == NULL) || (P_pOutputBuffer == NULL) || (P_pOutputSize == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_mac_generateTag(P_pAESCMACctx->mac_handle, P_pOutputBuffer, &tempOutputLen);

  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  /* Copy the cast to int32_t of tempOutputLen in order to not overwrite
     other data close to P_pOutputSize. */
  *P_pOutputSize = (int32_t)tempOutputLen;

  cmox_retval = cmox_mac_cleanup(P_pAESCMACctx->mac_handle);
  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = AES_SUCCESS;

error:
  return retval;
}

/* Initialization for AES-CMAC for Authentication TAG Verification */
int32_t AES_CMAC_Decrypt_Init(AESCMACctx_stt *P_pAESCMACctx)
{
  return (AES_CMAC_Encrypt_Init(P_pAESCMACctx));
}

/* AES-CMAC Data Processing */
int32_t AES_CMAC_Decrypt_Append(AESCMACctx_stt *P_pAESCMACctx,
                                const uint8_t *P_pInputBuffer,
                                int32_t        P_inputSize)
{
  return (AES_CMAC_Encrypt_Append(P_pAESCMACctx, P_pInputBuffer, P_inputSize));
}

/* AES Finalization of CMAC Mode */
int32_t AES_CMAC_Decrypt_Finish(AESCMACctx_stt *P_pAESCMACctx,
                                uint8_t       *P_pOutputBuffer,
                                int32_t       *P_pOutputSize)
{
  cmox_mac_retval_t cmox_retval;
  int32_t retval;

  if ((P_pAESCMACctx == NULL) || (P_pOutputSize == NULL))
  {
    retval = AES_ERR_BAD_PARAMETER;
    goto error;
  }

  (void)P_pOutputBuffer;

  *P_pOutputSize = 0;
  cmox_retval = cmox_mac_verifyTag(P_pAESCMACctx->mac_handle, P_pAESCMACctx->pmTag, NULL);

  if (cmox_retval == CMOX_MAC_AUTH_SUCCESS)
  {
    retval = AUTHENTICATION_SUCCESSFUL;
  }
  else if (cmox_retval == CMOX_MAC_AUTH_FAIL)
  {
    retval = AUTHENTICATION_FAILED;
  }
  else
  {
    retval = AES_ERR_BAD_PARAMETER;
  }

  (void)cmox_mac_cleanup(P_pAESCMACctx->mac_handle);

error:
  return retval;
}
