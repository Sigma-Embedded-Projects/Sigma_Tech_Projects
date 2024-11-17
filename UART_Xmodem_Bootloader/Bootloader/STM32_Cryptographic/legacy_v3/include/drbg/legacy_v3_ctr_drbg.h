/**
  *******************************************************************************
  * @file    legacy_v3_ctr_drbg.h
  * @author  MCD Application Team
  * @brief   Header file of CTR and DRBG helper for migration of cryptographics
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

#ifndef LEGACY_V3_CTR_DRBG_H
#define LEGACY_V3_CTR_DRBG_H

#include <stdint.h>
#include "drbg/cmox_ctr_drbg.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#define CRL_DRBG_AES128_STATE_SIZE          36u   /*!< Required size in bytes for a DRBG-AES128 state */
#define RNG_STATE_SIZE CRL_DRBG_AES128_STATE_SIZE
#define C_DRBG_AES128                       0u    /*!< Constant associated with the DRBG based on AES-128
                                                       to be used as DRBG for the random engine */


/**
  * @brief  Structure that contains the RNG stat
  */
typedef struct
{
  cmox_ctr_drbg_handle_t ctr_drbg_handle;

  cmox_drbg_handle_t *drbg_handle;

  uint8_t mRNGstate[RNG_STATE_SIZE];  /*!< Underlying DRBG context. It is initialized by \ref RNGinit */

  int32_t mDRBGtype;     /*!< Used to check if the random state has been mFlag */

  uint32_t mFlag;        /*!< Used to check if the random state has been mFlag */
}
RNGstate_stt;


/**
  * @brief  Structure used by RNGinit to initialize a DRBG
  */
typedef struct
{

  uint8_t *pmEntropyData;   /*!< The entropy data input */

  int32_t mEntropyDataSize; /*!< Size of the entropy data input */

  uint8_t *pmNonce;         /*!< The Nonce data */

  int32_t mNonceSize;       /*!< Size of the Nonce */

  uint8_t *pmPersData;      /*!< Personalization String */

  int32_t mPersDataSize;    /*!< Size of personalization string*/
}
RNGinitInput_stt;


/**
  * @brief  Structure used by RNGreseed to reseed a DRBG
  */
typedef struct
{

  uint8_t *pmEntropyData;   /*!< The entropy data input */

  int32_t mEntropyDataSize; /*!< Size of the entropy data input */

  uint8_t *pmAddInput;      /*!< Additional input */

  int32_t mAddInputSize;    /*!< Size of additional input */
}
RNGreInput_stt;

/**
  * @brief  Structure used by RNGgenBytes or RNGgenWords to provide the optional additional input
  */
typedef struct
{
  uint8_t *pmAddInput;      /*!< Additional input */

  int32_t mAddInputSize;    /*!< Size of additional input */
}
RNGaddInput_stt;


/* Exported functions ------------------------------------------------------- */
/* Reseed random **************************************************************/
/**
  * @brief  Reseed the random engine
  * @param[in]  P_pInputData Pointer to a client initialized RNGreInput_stt
  *               structure containing the required parameters for a DRBG reseed
  * @param[in,out]  P_pRandomState The RNG status that will be reseeded
  * @retval    RNG_SUCCESS Operation Successful
  * @retval    RNG_ERR_BAD_PARAMETER Some of the inputs were NULL
  * @retval    RNG_ERR_BAD_ADD_INPUT_SIZE Wrong size for P_pAddInput. It must be less than
  *            CRL_DRBG_AES_MAX_ADD_INPUT_LEN
  * @retval    RNG_ERR_BAD_ENTROPY_SIZE Wrong size for P_entropySize
  */
int32_t RNGreseed(const RNGreInput_stt *P_pInputData,
                  RNGstate_stt *P_pRandomState);

/* Initialize random **********************************************************/
/**
  * @brief  Initialize the random engine
  * @param[in]  P_pInputData   Pointer to an initialized RNGinitInput_stt structure
  * @param[out]  P_pRandomState The state of the random engine that will be initialized
  * @retval   RNG_SUCCESS Operation Successful
  * @retval   RNG_ERR_BAD_PARAMETER Some of the inputs were NULL
  * @retval   RNG_ERR_BAD_ENTROPY_SIZE Wrong size for P_pEntropyInput. It must be greater than
  *           CRL_DRBG_AES128_ENTROPY_MIN_LEN and less than CRL_DRBG_AES_ENTROPY_MAX_LEN
  * @retval   RNG_ERR_BAD_PERS_STRING_SIZE Wrong size for P_pPersStr. It must be less than
  *           CRL_DRBG_AES128_MAX_PERS_STR_LEN
  * @retval   RNG_ERR_BAD_NONCE_SIZE Wrong size for P_nonceSize. It must be less than CRL_DRBG_AES128_MAX_NONCE_LEN
  *  *  @note This function requires that:
  *  - P_pInputData.pmEntropyData points to a valid buffer containing entropy data
  *  - P_pInputData->mEntropyDataSize specifies the size of the entropy data (it should be greater than
  *    CRL_DRBG_AESx_ENTROPY_MIN_LEN and less than CRL_DRBG_AESx_ENTROPY_MAX_LEN, where x could be 128 or
  *    256 depending on the chosen DRBG method)
  *  - P_pInputData->pmNonce points to a valid Nonce or be set to NULL
  *  - P_pInputData->mNonceSize specifies the size of the Nonce or be set to zero
  *  - P_pInputData->pmPersData points to a valid Personalization String or be set to NULL
  *  - P_pInputData->mPersDataSize specifies the size of the Personalization String or be set to zero
  * @note See Section 4 of <a href ="csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">NIST SP 800-90A</a>
  *  to understand the meaning of Nonce, Personalization String and Entropy data
  */
int32_t RNGinit(const RNGinitInput_stt *P_pInputData,
                RNGstate_stt *P_pRandomState);

/* Free random ****************************************************************/
/**
  * @brief  Deinitialize a random engine state structure
  * @param[in,out]  P_pRandomState  The state of the random engine that will be removed
  * @retval    RNG_SUCCESS Operation Successful
  * @retval    RNG_ERR_BAD_PARAMETER P_pRandomState == NULL
  * @retval    RNG_ERR_UNINIT_STATE Random engine not initialized.
  */
int32_t RNGfree(RNGstate_stt *P_pRandomState);

/* Generate random octets to a buffer *****************************************/
/**
  * @brief  Generation of pseudorandom octets to a buffer
  * @param[in,out] *P_pRandomState The current state of the random engine
  * @param[in]     *P_pAddInput Optional Additional Input (can be NULL)
  * @param[out]    *P_pOutput The output buffer
  * @param[in]     P_OutLen  The number of random octets to generate
  * @retval    RNG_SUCCESS Operation Successful
  * @retval    RNG_ERR_BAD_PARAMETER P_pRandomState == NULL or P_pOutput == NULL && P_OutLen > 0
  * @retval    RNG_ERR_UNINIT_STATE Random engine not initialized.
  * @retval    RNG_ERR_RESEED_NEEDED Returned only if it's defined CRL_RANDOM_REQUIRE_RESEED. \n
  *              The count of number of requests between reseed has reached its limit.\n
  *              \b Reseed \b is \b necessary.
  * @retval    RNG_ERR_BAD_ADD_INPUT_SIZE Wrong size for the additional input.
  *               It should be P_pAddInput.mAddInputSize <= CRL_DRBG_AES_MAX_ADD_INPUT_LEN
  * @retval    RNG_ERR_BAD_REQUEST Internal RNG error
  * @note    The function supports to be called with P_OutLen==0, in this case P_pOutput can be NULL
  * @warning The user has to be careful to not invoke this function more than 2^48 times without
  *          calling the \ref RNGreseed function
  */
int32_t RNGgenBytes(RNGstate_stt *P_pRandomState,
                    const RNGaddInput_stt *P_pAddInput,
                    uint8_t *P_pOutput,
                    int32_t P_OutLen);

/* Return a random int32_t ****************************************************/
/**
  * @brief  Generation of a random uint32_t array
  * @param[in,out] *P_pRandomState  The random engine current state
  * @param[in]     *P_pAddInput Optional Additional Input (can be NULL)
  * @param[out]    *P_pWordBuf       The buffer where the uint32_t array will be stored
  * @param[in]     *P_BufSize        The number of uint32_t to generate.
  * @note   P_pWordBuf must be allocated to store P_BufLen*sizeof(uint32_t) octets.
  * @retval   RNG_SUCCESS Operation Successful
  * @retval   RNG_ERR_BAD_PARAMETER P_pRandomState == NULL or P_pOutput == NULL && P_OutLen > 0
  * @retval   RNG_ERR_UNINIT_STATE Random engine not initialized
  * @retval   RNG_ERR_RESEED_NEEDED Returned only if it's defined CRL_RANDOM_REQUIRE_RESEED. \n
  *              The count of number of requests between reseed has reached its limit.\n
  *              \b Reseed \b is \b necessary.
  * @retval   RNG_ERR_BAD_ADD_INPUT_SIZE Wrong size for the additional input.
  *               It should be P_pAddInput.mAddInputSize <= CRL_DRBG_AES_MAX_ADD_INPUT_LEN
  * @retval   RNG_ERR_BAD_REQUEST Internal RNG error
  * @note    The function supports to be called with P_BufSize==0, in this case P_pWordBuf can be NULL
  */
int32_t RNGgenWords(RNGstate_stt *P_pRandomState,
                    const RNGaddInput_stt *P_pAddInput,
                    uint32_t *P_pWordBuf,
                    int32_t P_BufSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* LEGACY_V3_CTR_DRBG_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
