/**
  *******************************************************************************
  * @file    legacy_v3_aes_xts.h
  * @author  MCD Application Team
  * @brief   Header file of AES XTS helper for migration of cryptographics
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

#ifndef LEGACY_V3_AES_XTS_H
#define LEGACY_V3_AES_XTS_H

#include <stdint.h>
#include "cipher/legacy_v3_aes.h"
#include "cipher/cmox_xts.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef struct
{
  cmox_xts_handle_t xts_handle;
  cmox_cipher_handle_t *cipher_handle;
  uint32_t   mContextId; /*!< Unique ID of this context. \b Not \b used in current implementation. */
  SKflags_et mFlags; /*!< 32 bit mFlags, used to perform keyschedule */
  int32_t   mIvSize; /*!< Size of the Initialization Vector in bytes */
  int32_t   mKeySize; /*!< Key length in bytes */
} AESXTSctx_stt; /*!< AES context structure for XTS mode */

/**
  * @brief Initialization for AES Encryption in XTS Mode
  * @param[in,out]    *P_pAESXTSctx  AES XTS context
  * @param[in]        *P_pKey        Buffer with an XTS key (whose size is either 32 or 64 bytes)
  * @param[in]        *P_pTweak      Buffer with the Tweak value (it is assumed to be of 16 bytes)
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_CONTEXT   Context was not initialized with valid values, see the note below.
  * @note \c P_pAESXTSctx.mKeySize (see \ref AESXTSctx_stt) must be set with  half of the size of the XTS key prior
  *       to calling this function.
  *           Or you can use the following values:
  *         - \ref CRL_AES128_KEY for a double 128 bit key
  *         - \ref CRL_AES256_KEY for a double 256 bit key
  * @note \c P_pAESXTSctx.mFlags must be set prior to calling this function. Default value is E_SK_DEFAULT.
  *          See \ref SKflags_et for details.
  * @note \c The Tweak is "The 128-bit value used to represent the logical position of the data being encrypted or
  *       decrypted with XTS-AES."
  * @note \c P_pTweak is assumed to be 16 bytes long.
  */
int32_t AES_XTS_Encrypt_Init(AESXTSctx_stt *P_pAESXTSctx, const uint8_t *P_pKey, const uint8_t *P_pIv);

/**
  * @brief AES Encryption in XTS Mode
  * @param[in,out] *P_pAESXTSctx     AES XTS, already initialized, context
  * @param[in]    *P_pInputBuffer   Input buffer
  * @param[in]     P_inputSize      Size of input data, expressed in bytes
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data,
  *                                 expressed in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_OPERATION   Append not allowed
  * @remark This function can be called multiple times, provided that \c P_inputSize is a multiple of 16.
            It can be called one last time with an input size > 16 and not multiple of 16, in this case
            the Ciphertext Stealing of XTS will be used.
  */
int32_t AES_XTS_Encrypt_Append(AESXTSctx_stt *P_pAESXTSctx, const uint8_t *P_pInputBuffer,
                               int32_t P_inputSize, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief AES Finalization of XTS Mode
  * @param[in,out]    *P_pAESXTSctx     AES XTS, already initialized, context
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data,
  *                                 expressed in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @remark    This function won't write output data, thus it can be skipped. \n It is kept for API compatibility.
  */
int32_t AES_XTS_Encrypt_Finish(AESXTSctx_stt *P_pAESXTSctx, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief Initialization for AES Decryption in XTS Mode
  * @param[in,out]    *P_pAESXTSctx  AES XTS context
  * @param[in]        *P_pKey        Buffer with an XTS key (whose size is either 32 or 64 bytes)
  * @param[in]        *P_pTweak      Buffer with the Tweak value (it is assumed to be of 16 bytes)
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_CONTEXT   Context was not initialized with valid values, see the note below.
  * @note \c P_pAESXTSctx.mKeySize (see \ref AESXTSctx_stt) must be set with  half of the size of the XTS key prior
  *       to calling this function.
  *           Or you can use the following values:
  *         - \ref CRL_AES128_KEY for a double 128 bit key
  *         - \ref CRL_AES256_KEY for a double 256 bit key
  * @note \c P_pAESXTSctx.mFlags must be set prior to calling this function. Default value is E_SK_DEFAULT.
  *          See \ref SKflags_et for details.
  * @note \c The Tweak is "The 128-bit value used to represent the logical position of the data being encrypted or
  *       decrypted with XTS-AES."
  * @note \c P_pTweak is assumed to be 16 bytes long.
  */
int32_t AES_XTS_Decrypt_Init(AESXTSctx_stt *P_pAESXTSctx, const uint8_t *P_pKey, const uint8_t *P_pIv);

/**
  * @brief AES Decryption in XTS Mode
  * @param[in,out] *P_pAESXTSctx     AES XTS, already initialized, context
  * @param[in]    *P_pInputBuffer   Input buffer
  * @param[in]     P_inputSize      Size of input data, expressed in bytes
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_OPERATION   Append not allowed
  * @remark This function can be called multiple times, provided that \c P_inputSize is a multiple of 16.
            It can be called one last time with an input size > 16 and not multiple of 16, in this case
            the Ciphertext Stealing of XTS will be used.
  */
int32_t AES_XTS_Decrypt_Append(AESXTSctx_stt *P_pAESXTSctx, const uint8_t *P_pInputBuffer, int32_t P_inputSize,
                               uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief AES Decryption Finalization of XTS Mode
  * @param[in,out] *P_pAESXTSctx     AES XTS, already initialized, context
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data, expressed
  *                                 in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @remark    This function won't write output data, thus it can be skipped. \n It is kept for API compatibility.
  * @remark This is a wrapper for \ref AES_XTS_Encrypt_Finish as the XTS Mode is equal in encryption
  *       and decryption
  */
int32_t AES_XTS_Decrypt_Finish(AESXTSctx_stt *P_pAESXTSctx, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* LEGACY_V3_AES_XTS_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
