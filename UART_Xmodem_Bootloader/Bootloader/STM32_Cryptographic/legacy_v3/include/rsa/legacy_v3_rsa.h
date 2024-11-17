/**
  ******************************************************************************
  * @file    legacy_v3_rsa.h
  * @author  MCD Application Team
  * @brief   Header file of RSA PKCS#1 v1.5 helper for migration of
  *          cryptographics library V3 to V4
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

#ifndef CMOX_HELPER_RSA_H
#define CMOX_HELPER_RSA_H

#include <stdint.h>
#include "drbg/legacy_v3_ctr_drbg.h"
#include "membuf/legacy_v3_membuf.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/**
  * @brief  Structure type for RSA public key
  */
typedef struct
{
  uint8_t  *pmModulus;    /*!< RSA Modulus */
  int32_t  mModulusSize;  /*!< Size of RSA Modulus */
  uint8_t  *pmExponent;   /*!< RSA Public Exponent */
  int32_t  mExponentSize; /*!< Size of RSA Public Exponent */
}
RSApubKey_stt;

/**
  * @brief  Structure type for RSA private key
  */
typedef struct
{
  uint8_t  *pmModulus;    /*!< RSA Modulus */
  int32_t  mModulusSize;  /*!< Size of RSA Modulus */
  uint8_t  *pmExponent;   /*!< RSA Private Exponent */
  int32_t  mExponentSize; /*!< Size of RSA Private Exponent */
}
RSAprivKey_stt;

/**
  * @brief Structure type for input/output of PKCS#1 v1.5 encryption/decryption operation
  */
typedef struct
{
  const uint8_t *pmInput; /*!< Pointer to input buffer */
  int32_t mInputSize;     /*!< Size of input buffer */
  uint8_t *pmOutput;      /*!< Pointer to output buffer */
}
RSAinOut_stt;

/**
  * @brief  Enumeration of possible hash functions
  */
typedef enum HashType_e
{
  E_MD5,          /*!< [UNSUPPORTED] MD5       */
  E_SHA1,         /*!<               SHA-1     */
  E_SHA224,       /*!<               SHA-224   */
  E_SHA256,       /*!<               SHA-256   */
  E_SHA384,       /*!<               SHA-384   */
  E_SHA512,       /*!<               SHA-512   */
} hashType_et;

/* Public functions */

/**
  * @brief PKCS#1v1.5 RSA Signature Generation Function
  * @param[in]  *P_pPrivKey   RSA private key structure (RSAprivKey_stt)
  * @param[in]  *P_pDigest    The message digest that will be signed
  * @param[in]  P_hashType    Identifies the type of Hash function used
  * @param[out] *P_pSignature The returned message signature
  * @param[in]  *P_pMemBuf    Pointer to the membuf_stt structure that will be used
  *                           to store the internal values required by computation
  * @retval RSA_SUCCESS               Operation Successful
  * @retval RSA_ERR_BAD_PARAMETER     Some of the inputs were NULL
  * @retval RSA_ERR_UNSUPPORTED_HASH  The Hash type passed doesn't correspond to any among the supported ones
  * @retval RSA_ERR_BAD_KEY           Some member of structure P_pPrivKey were invalid
  * @retval ERR_MEMORY_FAIL           Not enough memory left available
  * @retval RSA_ERR_MODULUS_TOO_SHORT RSA modulus is too short to handle this hash type
  * @note P_pSignature has to point to a memory area of suitable size (modulus size)
  */
int32_t RSA_PKCS1v15_Sign(const RSAprivKey_stt *P_pPrivKey,
                          const uint8_t        *P_pDigest,
                          hashType_et          P_hashType,
                          uint8_t              *P_pSignature,
                          membuf_stt           *P_pMemBuf);

/**
  * @brief PKCS#1v1.5 RSA Signature Verification Function
  * @param[in] *P_pPubKey    RSA public key structure (RSApubKey_stt)
  * @param[in] *P_pDigest    The hash digest of the message to be verified
  * @param[in] P_hashType    Identifies the type of Hash function used
  * @param[in] *P_pSignature The signature that will be checked
  * @param[in] *P_pMemBuf    Pointer to the membuf_stt structure that will be used
  *                          to store the internal values required by computation
  * @return Result of verification or Error
  * @retval SIGNATURE_VALID           The Signature is valid
  * @retval SIGNATURE_INVALID         The Signature is NOT valid
  * @retval RSA_ERR_BAD_PARAMETER     Some of the inputs were NULL
  * @retval RSA_ERR_UNSUPPORTED_HASH  The Hash type passed doesn't correspond to any among the supported ones
  * @retval ERR_MEMORY_FAIL           Not enough memory left available
  * @retval RSA_ERR_MODULUS_TOO_SHORT RSA modulus is too short to handle this hash type
  * @note P_pSignature has to point to a memory area of suitable size (modulus size)
  */
int32_t RSA_PKCS1v15_Verify(const RSApubKey_stt *P_pPubKey,
                            const uint8_t       *P_pDigest,
                            hashType_et         P_hashType,
                            const uint8_t       *P_pSignature,
                            membuf_stt          *P_pMemBuf);

/**
  * @brief Perform an RSA-PKCS#1 v1.5 Encryption using the public key
  * @param[in]     *P_pPubKey      The Public Key used to encrypt
  * @param[in,out] *P_pInOut_st    The input Data to encrypt
  * @param[in]     *P_pRandomState The state of the random engine
  * @param[in]     *P_pMemBuf      Pointer to the membuf_stt structure that will be used
  *                                to store the internal values required by computation
  * @retval RSA_SUCCESS Operation Successful
  * @retval RSA_ERR_BAD_PARAMETER if input parameters are not correct
  * @retval RSA_ERR_MESSAGE_TOO_LONG if input messagge to encrypt is too long (maximum size is Modulus Size - 11)
  * @retval RSA_ERR_BAD_OPERATION if something was wrong in the RSA encryption or in the random number generation
  * @note P_pOutputData has to point to a memory area of suitable size (modulus size)
  */
int32_t RSA_PKCS1v15_Encrypt(const RSApubKey_stt *P_pPubKey,
                             RSAinOut_stt        *P_pInOut_st,
                             RNGstate_stt        *P_pRandomState,
                             membuf_stt          *P_pMemBuf);

/**
  * @brief Perform an RSA-PKCS#1 v1.5 Decryption using the private key
  * @param[in]     *P_pPrivKey    The Private Key used to decrypt
  * @param[in,out] *P_pInOut_st   Structure keeping both input, input size and pointer to output buffer
  * @param[out]    *P_pOutputSize Pointer to the output decrypted data length
  * @param[in]     *P_pMemBuf     Pointer to the membuf_stt structure that will be used
  *                               to store the internal values required by computation
  * @retval RSA_SUCCESS     Operation Successful
  * @retval RSA_ERR_GENERIC Generic Decryption Error
  * @note P_pInOut_st->mInputSize has be equal to the modulus size, and P_pInOut_st->pmOutput should be not
  *       smaller than modulus size - 11
  * @warning Care shall be taken to ensure that an opponent cannot distinguish whether an error occurred,
  *          by error message or timing information. Otherwise an opponent may be able to obtain useful information
  *          about the decryption of the ciphertext, leading to a strengthened version of Bleichenbacher's attack\n
  *          [D. Bleichenbacher. Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard
  *           PKCS #1. In H. Krawczyk, editor, Advances in Cryptology - Crypto '98, volume 1462 of Lecture Notes
  *           in Computer Science, pp. 1-12. Springer Verlag, 1998]. \n
  *          This function will check the padding in constant time, but will nevertheless return an RSA_ERR_GENERIC,
  *          as the standard specifies, that should be handled with care by the caller.
  */
int32_t RSA_PKCS1v15_Decrypt(const RSAprivKey_stt *P_pPrivKey,
                             RSAinOut_stt         *P_pInOut_st,
                             int32_t              *P_pOutputSize,
                             membuf_stt           *P_pMemBuf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CMOX_HELPER_RSA_H */
