/**
  *******************************************************************************
  * @file    legacy_v3_sha224.h
  * @author  MCD Application Team
  * @brief   Header file of SHA-1 helper for the migration of cryptographics
  *          library V3 to V4
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

#ifndef LEGACY_V3_SHA224_H
#define LEGACY_V3_SHA224_H

#include <stdint.h>
#include "hash/cmox_sha224.h"
#include "hash/legacy_v3_hash.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#define CRL_SHA224_SIZE CMOX_SHA224_SIZE   /*!< Number of bytes (uint8_t) to store a SHA-224 digest. */


/**
  * @brief Structure for HASH context
  */
typedef struct
{
  cmox_sha224_handle_t sha_handle;    /*!< CMOX SHA224 handle */
  cmox_hash_handle_t *hash_handle;  /*!< Pointer to the CMOX hash handle pointer.
                                          It will point to the above sha_handle */
  int32_t  mTagSize;                /*!<  Size of the required Digest */
  HashFlags_et mFlags;              /*!< 32 bit mFlags, used to perform keyschedule */
} SHA224ctx_stt;

/**
  * @brief  Initialize a new SHA224 context
  * @param[in,out]  *P_pSHA224ctx The context that will be initialized
  * @retval HASH_SUCCESS Operation Successful
  * @retval HASH_ERR_BAD_PARAMETER Parameter P_pSHA224ctx is invalid
  * @note \c P_pSHA224ctx.mFlags must be set prior to calling this function. Default value is E_HASH_DEFAULT.
  *          See \ref HashFlags_et for details.
  * @note \c P_pSHA224ctx.mTagSize must be set with the size of the required message digest that will be generated
  *       by the \ref SHA224_Finish
  *          Possible values are values are from 1 to CRL_SHA224_SIZE (28)
  */
int32_t SHA224_Init(SHA224ctx_stt *P_pSHA224ctx);

/**
  * @brief  SHA224 Update function, process input data and update a SHA224ctx_stt
  * @param[in,out] *P_pSHA224ctx      The SHA224 context that will be updated
  * @param[in]     *P_pInputBuffer The data that will be processed using SHA224
  * @param[in]      P_inputSize    Size of input data, expressed in bytes
  * @retval HASH_SUCCESS Operation Successful
  * @retval HASH_ERR_BAD_PARAMETER  At least one of the parameters is a NULL pointer
  * @retval HASH_ERR_BAD_OPERATION  SHA224_Append can't be called after \ref SHA224_Finish has been called.
  * @remark This function can be called multiple times with no restrictions on the value of P_inputSize
  */
int32_t SHA224_Append(SHA224ctx_stt *P_pSHA224ctx, const uint8_t *P_pInputBuffer, int32_t P_inputSize);

/**
  * @brief  SHA224 Finish function, produce the output SHA224 digest
  * @param[in,out] *P_pSHA224ctx        The SHA224 context
  * @param[out] *P_pOutputBuffer  The buffer that will contain the digest
  * @param[out] *P_pOutputSize    The size of the data written to P_pOutputBuffer
  * @retval HASH_SUCCESS Operation Successful
  * @retval HASH_ERR_BAD_PARAMETER  At least one of the parameters is a NULL pointer
  * @retval HASH_ERR_BAD_CONTEXT P_pSHA224ctx was not initialized with valid values
  * @note   P_pSHA224ctx->mTagSize must contain a valid value, between 1 and CRL_SHA224_SIZE (28)
  *         before calling this function
  */
int32_t SHA224_Finish(SHA224ctx_stt *P_pSHA224ctx, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* LEGACY_V3_SHA224_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
