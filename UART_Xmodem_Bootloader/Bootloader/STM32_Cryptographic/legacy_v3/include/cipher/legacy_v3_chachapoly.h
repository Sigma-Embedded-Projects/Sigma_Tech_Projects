/**
  *******************************************************************************
  * @file    legacy_v3_chachapoly.h
  * @author  MCD Application Team
  * @brief   Header file of ChaCha20-Poly1305 helper for migration of
  *          cryptographics library V3 to V4
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

#ifndef LEGACY_V3_CHACHAPOLY_H
#define LEGACY_V3_CHACHAPOLY_H

#include "cipher/cmox_chachapoly.h"
#include "cipher/legacy_v3_aes.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef struct
{
  cmox_chachapoly_handle_t chachapoly_handle;
  cmox_cipher_handle_t *cipher_handle;
  const uint8_t *pmTag;    /*!< Pointer to Authentication TAG. This value must be set in decryption,
                                and this TAG will be verified */
  SKflags_et mFlags;       /*!< 32 bit mFlags, noty used kept for compatibility */
} ChaCha20Poly1305ctx_stt; /*!< Structure for ChaCha20-Poly1305 context */


/**
  * @brief Initialization for ChaCha20-Poly1305 AEAD Encryption Algorithm
  * @param[in,out] *P_pChaCha20Poly1305ctx  ChaCha20-Poly1305 context
  * @param[in]     *P_pKey                  ChaCha20-Poly1305 32 byte key
  * @param[in]     *P_pNonce                ChaCha20-Poly1305 12 byte Nonce
  *                                         (Number used Once)
  * @retval    CHACHA20POLY1305_SUCCESS Operation Successful
  * @retval    CHACHA20POLY1305_ERR_BAD_PARAMETER At least one of the parameters
  *            is a NULL pointer
  * @note      Output TAG will be of 16 bytes.
  */
int32_t ChaCha20Poly1305_Encrypt_Init(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                      const uint8_t *P_pKey,
                                      const uint8_t *P_pNonce);


/**
  * @brief ChaCha20-Poly1305 AAD (Additional Authenticated Data) processing function
  * @param[in,out] *P_pChaCha20Poly1305ctx  ChaCha20-Poly1305 context ( Initialized with
  *                      \ref ChaCha20Poly1305_Encrypt_Init or \ref ChaCha20Poly1305_Decrypt_Init)
  * @param[in]     *P_pInputBuffer  Data to be authenticated but not encrypted/decrytped
  * @param[in]      P_inputSize     Size (in bytes) of data at P_pInputBuffer
  * @retval    CHACHA20POLY1305_SUCCESS Operation Successful
  * @retval    CHACHA20POLY1305_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    CHACHA20POLY1305_ERR_BAD_OPERATION Call to \ref ChaCha20Poly1305_Header_Append is not allowed
  * @note This function can be called multiple times with P_inputSize multiple of 16 bytes.
  *       A single, last, call can be made with any value for P_inputSize
  */
int32_t ChaCha20Poly1305_Header_Append(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                       const uint8_t *P_pInputBuffer,
                                       int32_t P_inputSize);

/**
  * @brief ChaCha20-Poly1305 AEAD Encryption processing function
  * @param[in,out] *P_pChaCha20Poly1305ctx  ChaCha20-Poly1305 context
  *                    ( Initialized with \ref ChaCha20Poly1305_Encrypt_Init )
  * @param[in]     *P_pInputBuffer  Data to be authenticated and encrypted
  * @param[in]      P_inputSize     Size (in bytes) of data at P_pInputBuffer
  * @param[out]    *P_pOutputBuffer Output Buffer
  * @param[out]    *P_pOutputSize   Pointer to integer that will contain the size of written output data
  * @retval    CHACHA20POLY1305_SUCCESS Operation Successful
  * @retval    CHACHA20POLY1305_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    CHACHA20POLY1305_ERR_BAD_OPERATION Call to \ref ChaCha20Poly1305_Encrypt_Append is not allowed
  * @note This function can be called multiple times with P_inputSize multiple of 64 bytes.
  *       A single, last, call can be made with any value for P_inputSize
  */
int32_t ChaCha20Poly1305_Encrypt_Append(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                        const uint8_t *P_pInputBuffer,
                                        int32_t P_inputSize,
                                        uint8_t *P_pOutputBuffer,
                                        int32_t *P_pOutputSize);

/**
  * @brief ChaCha20-Poly1305 TAG generation function
  * @param[in,out] *P_pChaCha20Poly1305ctx  ChaCha20-Poly1305 context
  * @param[in]     *P_pOutputBuffer Where the TAG will be writted
  * @param[in]     *P_pOutputSize   Will contain the size of the written tag (=16)
  * @retval    CHACHA20POLY1305_SUCCESS Operation Successful
  * @retval    CHACHA20POLY1305_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    CHACHA20POLY1305_ERR_BAD_OPERATION Call to \ref ChaCha20Poly1305_Encrypt_Finish is not allowed
  * @note This function will write a 16 bytes TAG
  */
int32_t ChaCha20Poly1305_Encrypt_Finish(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                        uint8_t *P_pOutputBuffer,
                                        int32_t *P_pOutputSize);


/**
  * @brief Initialization for ChaCha20-Poly1305 AEAD Decryption Algorithm
  * @param[in,out] *P_pChaCha20Poly1305ctx  ChaCha20-Poly1305 context
  * @param[in]     *P_pKey                  ChaCha20-Poly1305 32 byte key
  * @param[in]     *P_pNonce                ChaCha20-Poly1305 12 byte Nonce (Number used Once)
  * @retval    CHACHA20POLY1305_SUCCESS Operation Successful
  * @retval    CHACHA20POLY1305_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @note      P_pChaCha20Poly1305ctx.pmTag must be written by the caller before calling
  *            \ref ChaCha20Poly1305_Decrypt_Finish
  * @remark    This function is just a helper for \ref ChaCha20Poly1305_Encrypt_Init
  */
int32_t ChaCha20Poly1305_Decrypt_Init(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                      const uint8_t *P_pKey,
                                      const uint8_t *P_pNonce);

/**
  * @brief ChaCha20-Poly1305 AEAD Decryption processing function
  * @param[in,out] *P_pChaCha20Poly1305ctx  ChaCha20-Poly1305 context
  *                    ( Initialized with \ref ChaCha20Poly1305_Decrypt_Init )
  * @param[in]     *P_pInputBuffer  Data to be authenticated and decrypted
  * @param[in]      P_inputSize     Size (in bytes) of data at P_pInputBuffer
  * @param[out]    *P_pOutputBuffer Output Buffer
  * @param[out]    *P_pOutputSize   Pointer to integer that will contain the size of written output data
  * @retval    CHACHA20POLY1305_SUCCESS Operation Successful
  * @retval    CHACHA20POLY1305_ERR_BAD_PARAMETER At least one of the parameters is a NULL pointer
  * @retval    CHACHA20POLY1305_ERR_BAD_OPERATION Call to \ref ChaCha20Poly1305_Decrypt_Append is not allowed
  * @note This function can be called multiple times with P_inputSize multiple of 64 bytes.
  *       A single, last, call can be made with any value for P_inputSize
  */
int32_t ChaCha20Poly1305_Decrypt_Append(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                        const uint8_t *P_pInputBuffer,
                                        int32_t P_inputSize,
                                        uint8_t *P_pOutputBuffer,
                                        int32_t *P_pOutputSize);

/**
  * @brief ChaCha20-Poly1305 Authentication TAG verification function
  * @param[in,out] *P_pChaCha20Poly1305ctx  ChaCha20-Poly1305 context
  * @param[in]     *P_pOutputBuffer Not used, could be NULL
  * @param[in]     *P_pOutputSize   Not used, could be NULL
  * @retval    CHACHA20POLY1305_ERR_BAD_PARAMETER P_pChaCha20Poly1305ctx is a NULL pointer
  * @retval    CHACHA20POLY1305_ERR_BAD_OPERATION Call to \ref ChaCha20Poly1305_Decrypt_Finish is not allowed
  * @retval    CHACHA20POLY1305_ERR_BAD_CONTEXT P_pChaCha20Poly1305ctx->pmTag == NULL
  * @retval    AUTHENTICATION_SUCCESSFUL TAG correctly verified
  * @retval    AUTHENTICATION_FAILED     Authentication \c Failed
  * @note This function requires that P_pChaCha20Poly1305ctx->pmTag is set by the caller and points to
  *       the TAG to be checked
  * @note The caller should just check the return value to be equal (or different) to AUTHENTICATION_SUCCESSFUL
  *       and accept (reject) the message/tag pair accordingly.
  */
int32_t ChaCha20Poly1305_Decrypt_Finish(ChaCha20Poly1305ctx_stt *P_pChaCha20Poly1305ctx,
                                        uint8_t *P_pOutputBuffer,
                                        int32_t *P_pOutputSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* LEGACY_V3_CHACHAPOLY_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
