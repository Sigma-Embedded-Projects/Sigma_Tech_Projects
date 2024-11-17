/**
  *******************************************************************************
  * @file    legacy_v3_aes_keywrap.h
  * @author  MCD Application Team
  * @brief   Header file of AES KeyWrap helper for migration of cryptographics
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

#ifndef LEGACY_V3_AES_KeyWrap_H
#define LEGACY_V3_AES_KeyWrap_H

#include <stdint.h>
#include "cipher/legacy_v3_aes.h"
#include "cipher/cmox_keywrap.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef struct
{
  cmox_keywrap_handle_t keywrap_handle;
  cmox_cipher_handle_t *cipher_handle;
  uint32_t   mContextId; /*!< Unique ID of this context. \b Not \b used in current implementation. */
  SKflags_et mFlags; /*!< 32 bit mFlags, used to perform keyschedule */
  int32_t   mIvSize; /*!< Size of the Initialization Vector in bytes */
  int32_t   mKeySize; /*!< Key length in bytes */
} AESKeyWrapctx_stt; /*!< AES context structure for KeyWrap mode */

typedef AESKeyWrapctx_stt AESKWctx_stt;/*!< Legacy redefine */
#define  CRL_AES_KWRAP_BLOCK 8  /*!< Number of uint8_t bytes in a Key Wrap Block */
#define  CRL_KWRAP_BLOCK_SIZE 2 /*!< Number of uint32_t words in a Key Wrap Block */

/**
  * @brief Initialization for AES KeyWrap Encryption
  * @param[in,out]    *P_pAESKWctx   AES Key Wrap context
  * @param[in]        *P_pKey        Buffer with the Key (KEK)
  * @param[in]        *P_pIv         Buffer with the 64 bits IV
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_CONTEXT   Context was not initialized with valid values, see the note below.
  * @note \c P_pAESKWctx.mKeySize (see \ref AESKWctx_stt) must be set with the size of the key prior to calling
  *       this function.
  *           Otherwise the following predefined values can be used:
  *         - \ref CRL_AES128_KEY
  *         - \ref CRL_AES192_KEY
  *         - \ref CRL_AES256_KEY
  * @note \c P_pAESKWctx.mFlags must be set prior to calling this function. Default value is E_SK_DEFAULT.
  *          See \ref SKflags_et for details.
  * @remark NIST defines the IV equal to 0xA6A6A6A6A6A6A6A6. In this implementation is a required input and
  *       can assume any value but its size is limited to 8 byte
  */
int32_t AES_KeyWrap_Encrypt_Init(AESKeyWrapctx_stt *P_pAESKeyWrapctx, const uint8_t *P_pKey, const uint8_t *P_pIv);

/**
  * @brief AES KeyWrap Wrapping function
  * @param[in,out] *P_pAESKWctx     AES KeyWrap, already initialized, context
  * @param[in]    *P_pInputBuffer   Input buffer, containing the Key to be wrapped
  * @param[in]     P_inputSize      Size of input data, expressed in bytes
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Pointer to integer that will contain the size of written output data,
  *                                 expressed in bytes
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_OPERATION   Append not allowed
  * @retval    AES_ERR_BAD_INPUT_SIZE   P_inputSize must be a non-zero multiple of 64 bits
  * @warning P_inputSize can be at maximum 256 or AES_ERR_BAD_INPUT_SIZE is returned
  * @note  This function can be called only once, passing in it the whole Key to be Wrapped.
  * @note  P_pOutputBuffer must be at least 8 bytes longer than P_pInputBuffer.
  * @note  P_inputSize must be a non-zero multiple of 64 bits
  */
int32_t AES_KeyWrap_Encrypt_Append(AESKeyWrapctx_stt *P_pAESKeyWrapctx, const uint8_t *P_pInputBuffer,
                                   int32_t P_inputSize, uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief Finalization for AES KeyWrap Encryption
  * @param[in,out] *P_pAESKWctx      AES KeyWrap, already initialized, context
  * @param[out]    *P_pOutputBuffer  Output buffer (won't be used)
  * @param[out]    *P_pOutputSize    Size of written output data. (It will be zero)
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL point
  * @remark    This function won't write output data, thus it can be skipped. \n It is kept for API compatibility.
  */
int32_t AES_KeyWrap_Encrypt_Finish(AESKeyWrapctx_stt *P_pAESKeyWrapctx, uint8_t *P_pOutputBuffer,
                                   int32_t *P_pOutputSize);

/**
  * @brief Initialization for AES KeyWrap Decryption
  * @param[in,out]    *P_pAESKWctx   AES Key Wrap context
  * @param[in]        *P_pKey        Buffer with the Key (KEK)
  * @param[in]        *P_pIv         Buffer with the 64 bits IV
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_CONTEXT   Context was not initialized with valid values, see the note below.
  * @note \c P_pAESKWctx.mKeySize (see \ref AESKWctx_stt) must be set with the size of the key prior to calling
  *       this function.
  *           Otherwise the following predefined values can be used:
  *         - \ref CRL_AES128_KEY
  *         - \ref CRL_AES192_KEY
  *         - \ref CRL_AES256_KEY
  * @note \c P_pAESKWctx.mFlags must be set prior to calling this function. Default value is E_SK_DEFAULT.
  *          See \ref SKflags_et for details.
  * @remark NIST defines the IV equal to 0xA6A6A6A6A6A6A6A6. In this implementation is a required input and
  *       can assume any value but its size is limited to 8 byte
  */
int32_t AES_KeyWrap_Decrypt_Init(AESKeyWrapctx_stt *P_pAESKeyWrapctx, const uint8_t *P_pKey, const uint8_t *P_pIv);

/**
  * @brief AES KeyWrap UnWrapping function
  * @param[in,out] *P_pAESKWctx     AES KeyWrap, already initialized, context
  * @param[in]    *P_pInputBuffer   Input buffer, containing the Key to be unwrapped
  * @param[in]     P_inputSize      Size of input data in uint8_t (octets)
  * @param[out]   *P_pOutputBuffer  Output buffer
  * @param[out]   *P_pOutputSize    Size of written output data in uint8_t
  * @retval    AES_SUCCESS Operation Successful
  * @retval    AES_ERR_BAD_PARAMETER   At least one of the parameters is a NULL pointer
  * @retval    AES_ERR_BAD_OPERATION   Append not allowed
  * @retval    AES_ERR_BAD_INPUT_SIZE  P_inputSize must be a non-zero multiple of 64 bits
  * @warning P_inputSize can be at maximum 264 or AES_ERR_BAD_INPUT_SIZE is returned
  * @note  This function can be called only once, passing in it the whole Key to be Wrapped.
  * @note  P_pOutputBuffer must be at least 8 bytes longer than P_pInputBuffer.
  * @note  P_inputSize must be a non-zero multiple of 64 bits
  */
int32_t AES_KeyWrap_Decrypt_Append(AESKeyWrapctx_stt *P_pAESKeyWrapctx, const uint8_t *P_pInputBuffer,
                                   int32_t P_inputSize,
                                   uint8_t *P_pOutputBuffer, int32_t *P_pOutputSize);

/**
  * @brief AES KeyWrap Finalization during Decryption, the authentication will be checked
  * @param[in,out] *P_pAESKWctx      AES KeyWrap, already initialized, context
  * @param[out]    *P_pOutputBuffer  Won't be used
  * @param[out]    *P_pOutputSize    Will contain zero
  * @returns    Result of Authentication or Error Code
  * @retval    AES_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    AUTHENTICATION_SUCCESSFUL The unwrapped key produced by \ref AES_KeyWrap_Decrypt_Append is valid
  * @retval    AUTHENTICATION_FAILED The unwrapped key produced by \ref AES_KeyWrap_Decrypt_Append is \b not valid
  */
int32_t AES_KeyWrap_Decrypt_Finish(AESKeyWrapctx_stt *P_pAESKeyWrapctx, uint8_t *P_pOutputBuffer,
                                   int32_t *P_pOutputSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* LEGACY_V3_AES_KeyWrap_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
