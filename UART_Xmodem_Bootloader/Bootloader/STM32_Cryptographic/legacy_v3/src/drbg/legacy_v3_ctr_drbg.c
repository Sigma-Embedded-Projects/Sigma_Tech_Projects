/**
  *******************************************************************************
  * @file    legacy_v3_aes_cbc.c
  * @author  MCD Application Team
  * @brief   This file provides CTR and DRBG functions of helper for migration
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

/* Includes ------------------------------------------------------------------*/
#include <stdlib.h>
#include "drbg/legacy_v3_ctr_drbg.h"
#include "err_codes.h"


/** @addtogroup UserAPI User Level API
  * @{
  */

/** @defgroup RNG Random Number Generation
  * @brief Implements the random engine
  * @{
  */

/* External variables --------------------------------------------------------*/
/* Private typedef -----------------------------------------------------------*/
/* Private defines -----------------------------------------------------------*/
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/* Initialize the random engine */
int32_t RNGinit(const RNGinitInput_stt *P_pInputData,
                RNGstate_stt *P_pRandomState)

{
  cmox_drbg_retval_t cmox_retval;
  int32_t retval;

  P_pRandomState->drbg_handle = cmox_ctr_drbg_construct(&P_pRandomState->ctr_drbg_handle, CMOX_CTR_DRBG_AES128_FAST);
  if (P_pRandomState->drbg_handle == NULL)
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_drbg_init(P_pRandomState->drbg_handle,
                               P_pInputData->pmEntropyData,
                               (size_t)P_pInputData->mEntropyDataSize,
                               P_pInputData->pmPersData,
                               (size_t)P_pInputData->mPersDataSize,
                               P_pInputData->pmNonce,
                               (size_t)P_pInputData->mNonceSize);

  if (cmox_retval != CMOX_DRBG_SUCCESS)
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = RNG_SUCCESS;

error:
  return retval;
}

/* Deinitialize a random engine state structure */
int32_t RNGfree(RNGstate_stt *P_pRandomState)
{
  cmox_drbg_retval_t cmox_retval;
  int32_t retval;

  cmox_retval = cmox_drbg_cleanup(P_pRandomState->drbg_handle);

  if (cmox_retval != CMOX_DRBG_SUCCESS)
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = RNG_SUCCESS;

error:
  return retval;
}

/* Reseed the random engine */
int32_t RNGreseed(const RNGreInput_stt *P_pInputData,
                  RNGstate_stt *P_pRandomState)
{
  cmox_drbg_retval_t cmox_retval;
  int32_t retval;
  if (P_pRandomState == NULL)
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }
  if (P_pInputData == NULL)
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_drbg_reseed(P_pRandomState->drbg_handle,
                                 P_pInputData->pmEntropyData,
                                 (size_t)P_pInputData->mEntropyDataSize,
                                 P_pInputData->pmAddInput,
                                 (size_t)P_pInputData->mAddInputSize);

  if (cmox_retval != CMOX_DRBG_SUCCESS)
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = RNG_SUCCESS;

error:
  return retval;
}


/* Generation of pseudorandom octets to a buffer */
int32_t RNGgenBytes(RNGstate_stt *P_pRandomState,
                    const RNGaddInput_stt *P_pAddInput,
                    uint8_t *P_pOutput,
                    int32_t P_OutLen)
{
  cmox_drbg_retval_t cmox_retval;
  int32_t retval;

  if ((P_pRandomState == NULL) || ((P_pOutput == NULL) && (P_OutLen > 0)))
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }

  if (P_pAddInput == NULL)
  {
    cmox_retval = cmox_drbg_generate(P_pRandomState->drbg_handle, NULL, 0, P_pOutput, (size_t) P_OutLen);
  }
  else
  {
    cmox_retval = cmox_drbg_generate(P_pRandomState->drbg_handle,
                                     P_pAddInput->pmAddInput,
                                     (size_t)(P_pAddInput->mAddInputSize),
                                     P_pOutput,
                                     (size_t) P_OutLen);
  }

  if (cmox_retval != CMOX_DRBG_SUCCESS)
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = RNG_SUCCESS;

error:
  return retval;
}

/* Generation of a random uint32_t array */
int32_t RNGgenWords(RNGstate_stt *P_pRandomState,
                    const RNGaddInput_stt *P_pAddInput,
                    uint32_t *P_pWordBuf,
                    int32_t P_BufSize)
{
  int32_t retval;
  cmox_drbg_retval_t cmox_retval;

  if ((P_pRandomState == NULL) || ((P_pWordBuf == NULL) && (P_BufSize > 0)))
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }

  cmox_retval = cmox_drbg_generate(P_pRandomState->drbg_handle,
                                   P_pAddInput->pmAddInput,
                                   (size_t)P_pAddInput->mAddInputSize,
                                   (uint8_t *)P_pWordBuf,
                                   (size_t) P_BufSize);
  if (cmox_retval != CMOX_DRBG_SUCCESS)
  {
    retval = RNG_ERR_BAD_PARAMETER;
    goto error;
  }

  retval = RNG_SUCCESS;

  /* The following is used to produce the same ints on big endian and little endian cpus.
  * Since the random are written as bytes into a int32_t arrays, different endianness means
  * different int32_t values. If the cpu is big endian then we swap the bytes.
  * It has been decided to do it on big endian cpus to not slow down little endian
  * cpus, because they're more common */

error:
  return retval;
}


/**
  * @}
  */

/**
  * @}
  */



/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
