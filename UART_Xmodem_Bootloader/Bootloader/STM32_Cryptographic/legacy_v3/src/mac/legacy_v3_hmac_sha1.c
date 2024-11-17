/**
  *******************************************************************************
  * @file    legacy_v3_hmac_sha1.c
  * @author  MCD Application Team
  * @brief   This file provides HMAC SHA1 functions of helper for
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

#include "mac/legacy_v3_hmac_sha1.h"
#include "err_codes.h"

/* Initialize a new HMAC SHA1 context */
int32_t HMAC_SHA1_Init(HMAC_SHA1ctx_stt *P_pHMAC_SHA1ctx)
{
  cmox_mac_retval_t cmox_retval;
  int32_t retval;

  if (P_pHMAC_SHA1ctx == NULL)
  {
    retval = HASH_ERR_BAD_PARAMETER;
    goto error;
  }
  P_pHMAC_SHA1ctx->mac_handle = cmox_hmac_construct(&P_pHMAC_SHA1ctx->hmac_handle,
                                                    CMOX_HMAC_SHA1);
  if (P_pHMAC_SHA1ctx->mac_handle == NULL)
  {
    retval = HASH_ERR_BAD_PARAMETER;
    goto error;
  }
  cmox_retval = cmox_mac_init(P_pHMAC_SHA1ctx->mac_handle);
  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = HASH_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_mac_setTagLen(P_pHMAC_SHA1ctx->mac_handle, (size_t)P_pHMAC_SHA1ctx->mTagSize);
  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = HASH_ERR_BAD_CONTEXT;
    goto error;
  }

  cmox_retval = cmox_mac_setKey(P_pHMAC_SHA1ctx->mac_handle,
                                P_pHMAC_SHA1ctx->pmKey,
                                (size_t)P_pHMAC_SHA1ctx->mKeySize);
  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = HASH_ERR_BAD_CONTEXT;
    goto error;
  }

  retval = HASH_SUCCESS;

error:
  return retval;
}

/* HMAC-SHA1 Update function, process input data and update a HMAC_SHA1ctx_stt */
int32_t HMAC_SHA1_Append(HMAC_SHA1ctx_stt *P_pHMAC_SHA1ctx, const uint8_t *P_pInputBuffer, int32_t P_inputSize)
{
  cmox_mac_retval_t cmox_retval;
  int32_t retval;

  if ((P_pHMAC_SHA1ctx == NULL) || (P_pInputBuffer == NULL) || (P_inputSize < 0))
  {
    retval = HASH_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_mac_append(P_pHMAC_SHA1ctx->mac_handle, P_pInputBuffer, (size_t)P_inputSize);

  if (cmox_retval == CMOX_MAC_ERR_BAD_OPERATION)
  {
    retval = HASH_ERR_BAD_OPERATION;
    goto error;
  }

  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = HASH_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = HASH_SUCCESS;

error:
  return retval;
}

/* HMAC-SHA1 Finish function, produce the output HMAC-SHA1 tag */
int32_t HMAC_SHA1_Finish(HMAC_SHA1ctx_stt *P_pHMAC_SHA1ctx, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize)
{
  cmox_mac_retval_t cmox_retval;
  int32_t retval;
  /* Temporal value for storing the computed output length. This is needed
     because of the possible (e.g. in 64 bits architectures) different dimension
     between int32_t (used in legacy helper) and size_t (used by the library
     for specifying lengths). */
  size_t tempOutputLen;

  if ((P_pHMAC_SHA1ctx == NULL) || (P_pOutputBuffer == NULL) || (P_pOutputSize == NULL))
  {
    retval = HASH_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_mac_generateTag(P_pHMAC_SHA1ctx->mac_handle, P_pOutputBuffer, &tempOutputLen);

  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = HASH_ERR_BAD_PARAMETER;
    goto error;
  }

  /* Copy the cast to int32_t of tempOutputLen in order to not overwrite
     other data close to P_pOutputSize. */
  *P_pOutputSize = (int32_t)tempOutputLen;

  cmox_retval = cmox_mac_cleanup(P_pHMAC_SHA1ctx->mac_handle);
  if (cmox_retval != CMOX_MAC_SUCCESS)
  {
    retval = HASH_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = HASH_SUCCESS;

error:
  return retval;
}
