/**
  *******************************************************************************
  * @file    legacy_v3_aes_cfb.h
  * @author  MCD Application Team
  * @brief   Header file of AES CFB helper for migration of cryptographics
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

#ifndef LEGACY_V3_AES_CFB_H
#define LEGACY_V3_AES_CFB_H

#include <stdint.h>
#include "cipher/legacy_v3_aes.h"
#include "cipher/cmox_cfb.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef struct
{
  cmox_cfb_handle_t cfb_handle;
  cmox_cipher_handle_t *cipher_handle;
  uint32_t   mContextId; /*!< Unique ID of this context. \b Not \b used in current implementation. */
  SKflags_et mFlags; /*!< 32 bit mFlags, used to perform keyschedule */
  int32_t   mIvSize; /*!< Size of the Initialization Vector in bytes */
  int32_t   mKeySize; /*!< Key length in bytes */
} AESCFBctx_stt; /*!< AES context structure for CFB mode */

/**
  * @brief Initialization for AES Encryption in CFB Mode
  * @param[in,out]    *P_pAESCFBctx  AES CFB context
  * @param[in]        *P_pKey        Buffer with the Key
  * @param[in]        *P_pIv         Buffer with the IV
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_CONTEXT   Context was not initialized with valid values, see the note below.
  * @note \c P_pAESCFBctx.mKeySize (see \ref AESCFBctx_stt) must be set with the size of the key prior to calling
  *       this function.
  *           Instead of the size of the key, you can also use the following predefined values:
  *         - \ref CRL_AES128_KEY
  *         - \ref CRL_AES192_KEY
  *         - \ref CRL_AES256_KEY
  * @note \c P_pAESCFBctx.mFlags must be set prior to calling this function. Default value is E_SK_DEFAULT.
  *          See \ref SKflags_et for details.
  * @note \c P_pAESCFBctx.mIvSize must be set with the size of the IV (default \ref CRL_AES_BLOCK) prior to calling
          this function.
  */
int32_t AES_CFB_Encrypt_Init(AESCFBctx_stt *P_pAESCFBctx, const uint8_t *P_pKey, const uint8_t *P_pIv);

/**
  * @brief AES Encryption in CFB Mode
  * @param[in,out] *P_pAESCFBctx     AES CFB, already initialized, context
  * @param[in]    *P_pInputBuffer   Input buffer
  * @param[in]     P_inputSize      Size of input data, expressed in bytes
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_OPERATION   Append not allowed
  * @remark This function can be called multiple times, provided that \c P_inputSize is a multiple of 16.
  *          The last call can have any input size.
  */
int32_t AES_CFB_Encrypt_Append(AESCFBctx_stt *P_pAESCFBctx, const uint8_t *P_pInputBuffer,
                               int32_t P_inputSize, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief AES Finalization of CFB Mode
  * @param[in,out]    *P_pAESCFBctx     AES CFB, already initialized, context
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @remark    This function won't write output data, thus it can be skipped. \n It is kept for API compatibility.
  */
int32_t AES_CFB_Encrypt_Finish(AESCFBctx_stt *P_pAESCFBctx, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief Initialization for AES Decryption in CFB Mode
  * @param[in,out]    *P_pAESCFBctx  AES CFB context
  * @param[in]        *P_pKey        Buffer with the Key
  * @param[in]        *P_pIv         Buffer with the IV
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_CONTEXT   Context was not initialized with valid values, see the note below.
  * @note \c P_pAESCFBctx.mKeySize (see \ref AESCFBctx_stt) must be set with the size of the key prior to calling
  *       this function.
  *           Instead of the size of the key, you can also use the following predefined values:
  *         - \ref CRL_AES128_KEY
  *         - \ref CRL_AES192_KEY
  *         - \ref CRL_AES256_KEY
  * @note \c P_pAESCFBctx.mFlags must be set prior to calling this function. Default value is E_SK_DEFAULT.
  *          See \ref SKflags_et for details.
  * @note \c P_pAESCFBctx.mIvSize must be set with the size of the IV (default \ref CRL_AES_BLOCK) prior to calling
  *       this function.
  */
int32_t AES_CFB_Decrypt_Init(AESCFBctx_stt *P_pAESCFBctx, const uint8_t *P_pKey, const uint8_t *P_pIv);

/**
  * @brief AES Decryption in CFB Mode
  * @param[in,out] *P_pAESCFBctx     AES CFB, already initialized, context
  * @param[in]    *P_pInputBuffer   Input buffer
  * @param[in]     P_inputSize      Size of input data, expressed in bytes
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_OPERATION   Append not allowed
  * @remark This function can be called multiple times, provided that \c P_inputSize is a multiple of 16.
  *          The last call can have any input size.
  */
int32_t AES_CFB_Decrypt_Append(AESCFBctx_stt *P_pAESCFBctx, const uint8_t *P_pInputBuffer, int32_t P_inputSize,
                               uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief AES Decryption Finalization of CFB Mode
  * @param[in,out] *P_pAESCFBctx     AES CFB, already initialized, context
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @remark    This function won't write output data, thus it can be skipped. \n It is kept for API compatibility.
  */
int32_t AES_CFB_Decrypt_Finish(AESCFBctx_stt *P_pAESCFBctx, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* LEGACY_V3_AES_CFB_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
