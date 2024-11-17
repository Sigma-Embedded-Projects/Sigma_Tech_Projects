/**
  *******************************************************************************
  * @file    legacy_v3_aes_ecb.h
  * @author  MCD Application Team
  * @brief   Header file of AES ECB helper for migration of cryptographics
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

#ifndef LEGACY_V3_AES_ECB_H
#define LEGACY_V3_AES_ECB_H

#include <stdint.h>
#include "cipher/legacy_v3_aes.h"
#include "cipher/cmox_ecb.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef struct
{
  cmox_ecb_handle_t ecb_handle;
  cmox_cipher_handle_t *cipher_handle;
  uint32_t   mContextId; /*!< Unique ID of this context. \b Not \b used in current implementation. */
  SKflags_et mFlags; /*!< 32 bit mFlags, used to perform keyschedule */
  int32_t   mIvSize; /*!< Size of the Initialization Vector in bytes */
  int32_t   mKeySize; /*!< Key length in bytes */
} AESECBctx_stt; /*!< AES context structure for ECB mode */

/**
  * @brief Initialization for AES Encryption in ECB Mode
  * @param[in,out]    *P_pAESECBctx  AES ECB context
  * @param[in]        *P_pKey        Buffer with the Key
  * @param[in]        *P_pIv         Buffer with the IV (Can be NULL since no IV is required in ECB)
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_CONTEXT   Context was not initialized with valid values, see the note below.
  * @note \c P_pAESECBctx.mKeySize (see \ref AESECBctx_stt) must be set with the size of the key prior to calling
  *       this function.
  *           Instead of the size of the key, you can also use the following predefined values:
  *         - \ref CRL_AES128_KEY
  *         - \ref CRL_AES192_KEY
  *         - \ref CRL_AES256_KEY
  * @note \c P_pAESECBctx.mFlags must be set prior to calling this function. Default value is E_SK_DEFAULT.
  *          See \ref SKflags_et for details.
  * @remark In ECB the IV is not used, so the value of \c P_pIv is not checked or used
  */
int32_t AES_ECB_Encrypt_Init(AESECBctx_stt *P_pAESECBctx, const uint8_t *P_pKey, const uint8_t *P_pIv);

/**
  * @brief AES Encryption in ECB Mode
  * @param[in]    *P_pAESECBctx     AES ECB, already initialized, context
  * @param[in]    *P_pInputBuffer   Input buffer
  * @param[in]     P_inputSize      Size of input data, expressed in bytes
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER   At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_INPUT_SIZE  The size of the input is not a multiple of CRL_AES_BLOCK
  * @retval    AES_ERR_BAD_OPERATION   Append not allowed
  * @remark This function can be called multiple times, provided that \c P_inputSize is a multiple of 16
  */
int32_t AES_ECB_Encrypt_Append(AESECBctx_stt *P_pAESECBctx, const uint8_t *P_pInputBuffer,
                               int32_t P_inputSize, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief AES Encryption Finalization of ECB Mode
  * @param[in,out]    *P_pAESECBctx     AES ECB, already initialized, context
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @remark    This function won't write output data, thus it can be skipped. \n It is kept for API compatibility.
  */
int32_t AES_ECB_Encrypt_Finish(AESECBctx_stt *P_pAESECBctx, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief Initialization for AES Decryption in ECB Mode
  * @param[in,out]    *P_pAESECBctx  AES ECB context
  * @param[in]        *P_pKey        Buffer with the Key
  * @param[in]        *P_pIv         Buffer with the IV
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_CONTEXT   Context was not initialized with valid values, see the note below.
  * @note \c P_pAESECBctx.mKeySize (see \ref AESECBctx_stt) must be set with the size of the key prior to calling
  *       this function.
  *           Instead of the size of the key, you can also use the following predefined values:
  *         - \ref CRL_AES128_KEY
  *         - \ref CRL_AES192_KEY
  *         - \ref CRL_AES256_KEY
  * @note \c P_pAESECBctx.mFlags must be set prior to calling this function. Default value is E_SK_DEFAULT.
  *          See \ref SKflags_et for details.
  * @remark In ECB the IV is not used, so the value of \c P_pIv is not checked or used
  */
int32_t AES_ECB_Decrypt_Init(AESECBctx_stt *P_pAESECBctx, const uint8_t *P_pKey, const uint8_t *P_pIv);

/**
  * @brief AES Decryption in ECB Mode
  * @param[in]    *P_pAESECBctx     AES ECB, already initialized, context
  * @param[in]    *P_pInputBuffer   Input buffer
  * @param[in]     P_inputSize      Size of input data, expressed in bytes
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_INPUT_SIZE  The size of the input is not a multiple of CRL_AES_BLOCK
  * @retval    AES_ERR_BAD_OPERATION   Append not allowed
  * @remark This function can be called multiple times, provided that \c P_inputSize is a multiple of 16
  */
int32_t AES_ECB_Decrypt_Append(AESECBctx_stt *P_pAESECBctx, const uint8_t *P_pInputBuffer, int32_t P_inputSize,
                               uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief AES Decryption Finalization of ECB Mode
  * @param[in,out]    *P_pAESECBctx     AES ECB, already initialized, context
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @remark    This function won't write output data, thus it can be skipped. \n It is kept for API compatibility.
  */
int32_t AES_ECB_Decrypt_Finish(AESECBctx_stt *P_pAESECBctx, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* LEGACY_V3_AES_ECB_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
