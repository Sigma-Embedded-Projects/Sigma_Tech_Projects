/**
  ******************************************************************************
  * @file    legacy_v3_ecc.h
  * @author  MCD Application Team
  * @brief   Header file of ECDH and ECDSA helper for migration of
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

#ifndef CMOX_HELPER_ECC_H
#define CMOX_HELPER_ECC_H

#include <stdint.h>
#include "drbg/legacy_v3_ctr_drbg.h"
#include "membuf/legacy_v3_membuf.h"
#include "ecc/cmox_ecc.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/**
  * @brief Elliptic Curve structure definition
  */
typedef struct
{
  const uint8_t *pmA;           /*!< pointer to parameter "a" */
  uint32_t mAsize;              /*!< size of parameter "a" */
  const uint8_t *pmB;           /*!< pointer to parameter "b" */
  uint32_t mBsize;              /*!< size of parameter "b" */
  const uint8_t *pmP;           /*!<pointer to parameter "p" */
  uint32_t mPsize;              /*!<size of parameter "p" */
  const uint8_t *pmN;           /*!< pointer to parameter "n" */
  uint32_t mNsize;              /*!< size of parameter "n" */
  const uint8_t *pmGx;          /*!< pointer to x coordinate of generator point */
  uint32_t mGxsize;             /*!< size of x coordinate of generator point */
  const uint8_t *pmGy;          /*!< pointer to y coordinate of generator point */
  uint32_t mGysize;             /*!< size of y coordinate of generator point */
  cmox_ecc_impl_t pmInternalEC; /*!< Pointer to internal structure for handling the parameters */
  cmox_ecc_handle_t cmox_ctx;   /*!< CMOX ECC public context */
} EC_stt;

/**
  * @brief ECC Point structure definition
  */
typedef struct
{
  uint8_t *pPoint;
  const EC_stt *pCurve;
} ECpoint_stt;

/**
  * @brief Point coordinate type enum definition
  */
typedef enum
{
  E_ECC_POINT_COORDINATE_X = 0, /*!< Coordinate X */
  E_ECC_POINT_COORDINATE_Y = 1, /*!< Coordinate Y */
  E_ECC_POINT_COORDINATE_Z = 2, /*!< Coordinate Z (NOT USED IN THIS IMPLEMENTATION) */
} ECcoordinate_et;

/**
  * @brief Point flag type enum definition
  */
typedef enum
{
  E_POINT_GENERAL = 0,    /*!< Point is not normalized (Coordinate Z != 1) (NOT USED IN THIS IMPLEMENTATION) */
  E_POINT_NORMALIZED = 1, /*!< Point is normalized (Coordinate Z == 1)*/
  E_POINT_INFINITY = 2,   /*!< Point is the O point (NOT USED IN THIS IMPLEMENTATION) */
  E_POINT_MONTY = 4       /*!< Point's coordinates expressed in Montgomery domain (NOT USED IN THIS IMPLEMENTATION) */
} ECPntFlags_et;

/**
  * @brief Private Key structure definition
  */
typedef struct
{
  uint8_t *pD;          /*!< Private key byte byffer (most significant byte first) */
  const EC_stt *pCurve; /*!< ECC Curve structure pointer */
} ECCprivKey_stt;

/**
  * @brief Signature result structure definition
  */
typedef struct
{
  uint8_t *pSig;        /*!< Signature byte byffer */
  const EC_stt *pCurve; /*!< ECC Curve structure pointer */
} ECDSAsignature_stt;

/**
  * @brief Enumeration for the values inside the ECDSA signature
  */
typedef enum ECDSAsignValues_e
{
  E_ECDSA_SIGNATURE_R_VALUE = 0,  /*!< Value R */
  E_ECDSA_SIGNATURE_S_VALUE = 1,  /*!< Value S */
} ECDSAsignValues_et;

/**
  * @brief ECDSA signing structure definition
  */
typedef struct
{
  ECCprivKey_stt *pmPrivKey;  /*!<  Pointer to the ECC Private Key used in the verification */
  EC_stt         *pmEC;       /*!<  Pointer to Elliptic Curve parameters */
  RNGstate_stt   *pmRNG;      /*!<  Pointer to an Initialized Random Engine Status */
} ECDSAsignCtx_stt;

/**
  * @brief ECDSA verifying structure definition
  */
typedef struct
{
  ECpoint_stt *pmPubKey;  /*!<  Pointer to the ECC Public Key used in the verification */
  EC_stt      *pmEC;      /*!<  Pointer to Elliptic Curve parameters */
} ECDSAverifyCtx_stt;

/* Public functions */

/**
  * @brief         Initialize the elliptic curve parameters into a EC_stt structure
  * @param[in,out] *P_pECctx  The \ref EC_stt context with the parameters of the ellliptic curve used
  * @param[in,out] *P_pMemBuf Pointer to the \ref membuf_stt structure that will be used to store the
  *                           Elliptic Curve internal values.
  * @retval        ECC_SUCCESS           Operation Successful
  * @retval        ECC_ERR_BAD_PARAMETER \c P_pECctx == NULL
  * @retval        ECC_ERR_BAD_CONTEXT   Some values inside \c P_pECctx are invalid
  * @retval        ERR_MEMORY_FAIL       There is no enough memory.
  * @retval        MATH_ERR_INTERNAL     Generic MATH error
  * @note P_pMemBuf must be properly initialized before calling this function. See \ref membuf_stt
  * @note This function will keep some value stored in membuf_stt.pmBuf, therefore when exiting this function
  *       membuf_stt.mUsed won't be set to zero. The caller can use the same P_pMemBuf also for other functions.
  *       The memory will be freed when \ref ECCfreeEC will be called
  */
int32_t ECCinitEC(EC_stt *P_pECctx, membuf_stt *P_pMemBuf);

/**
  * @brief  De-initialize an EC_stt context
  * @param[in,out] *P_pECctx  Pointer to the EC_stt structure containing the curve parameters to be freed
  * @param[in,out] *P_pMemBuf Pointer to the membuf_stt structure that holds the Elliptic Curve internal values.
  * @retval        ECC_SUCCESS            Operation Successful
  * @retval        ECC_ERR_BAD_PARAMETER  P_pECctx == NULL
  * @retval        ECC_ERR_BAD_CONTEXT    Some values inside P_pECctx are invalid
  */
int32_t ECCfreeEC(EC_stt *P_pECctx, membuf_stt *P_pMemBuf);

/**
  * @brief         Initialize an ECC point
  * @param[out]    **P_ppECPnt The point that will be initialized
  * @param[in]     *P_pECctx   The \ref EC_stt containing the Elliptic Curve Parameters
  * @param[in,out] *P_pMemBuf  Pointer to the membuf_stt structure that will be used to store the
  *                            Elliptic Curve Point internal values.
  * @retval        ECC_SUCCESS           Operation Successful
  * @retval        ECC_ERR_BAD_PARAMETER P_pECctx == NULL
  * @retval        ECC_ERR_BAD_CONTEXT   Some values inside P_pECctx are invalid
  * @retval        ERR_MEMORY_FAIL       There is no enough memory
  * @note This function will keep some value stored in membuf_stt.pmBuf, therefore when exiting this function
  *       membuf_stt.mUsed will be greater than it was before the call.
  *       The memory will be freed when \ref ECCfreePoint will be called
  */
int32_t ECCinitPoint(ECpoint_stt **P_ppECPnt, const EC_stt *P_pECctx, membuf_stt *P_pMemBuf);

/**
  * @brief         Free Elliptic curve point
  * @param[in,out] *P_pECPnt  The point that will be freed
  * @param[in,out] *P_pMemBuf Pointer to the membuf_stt structure that stores the Elliptic Curve Point internal values
  * @retval        ECC_SUCCESS           Operation Successful
  * @retval        ECC_ERR_BAD_PARAMETER P_pECPnt == NULL || P_pMemBuf == NULL
  * @retval        ECC_ERR_BAD_CONTEXT   *P_pECPnt == NULL
  */
int32_t ECCfreePoint(ECpoint_stt **P_ppECPnt, membuf_stt *P_pMemBuf);

/**
  * @brief         Set the value of one of coordinate of an ECC point
  * @param[in,out] *P_pECPnt           The ECC point that will have a coordinate set
  * @param[in]     P_Coordinate        Flag used to select which coordinate must be set (see \ref ECcoordinate_et)
  * @param[in]     *P_pCoordinateValue Pointer to an uint8_t array that contains the value to be set
  * @param[in]     P_coordinateSize    The size in bytes of P_pCoordinateValue
  * @retval        ECC_SUCCESS           Operation Successful
  * @retval        ECC_ERR_BAD_PARAMETER One of the input parameters is invalid
  * @retval        MATH_ERR_INTERNAL     Generic MATH error
  */
int32_t ECCsetPointCoordinate(ECpoint_stt     *P_pECPnt,
                              ECcoordinate_et P_Coordinate,
                              const uint8_t   *P_pCoordinateValue,
                              int32_t         P_coordinateSize);

/**
  * @brief      Get the value of one of coordinate of an ECC point
  * @param[in]  *P_pECPnt           The ECC point from which extract the coordinate
  * @param[in]  P_Coordinate        Flag used to select which coordinate must be retrieved (see \ref ECcoordinate_et)
  * @param[out] *P_pCoordinateValue Pointer to an uint8_t array that will contain the returned coordinate
  * @param[out] *P_pCoordinateSize  Pointer to an integer that will contain the size of the returned coordinate
  * @retval     ECC_SUCCESS           Operation Successful
  * @retval     ECC_ERR_BAD_PARAMETER One of the input parameters is invalid
  * @retval     MATH_ERR_INTERNAL     Generic MATH error
  */
int32_t ECCgetPointCoordinate(const ECpoint_stt *P_pECPnt,
                              ECcoordinate_et   P_Coordinate,
                              uint8_t           *P_pCoordinateValue,
                              int32_t           *P_pCoordinateSize);
/**
  * @brief     Returns the point flag (actually only \ref E_POINT_NORMALIZED is used in this implementation)
  * @param[in] *P_pECPnt The point whose flag will be returned
  * @returns   E_POINT_NORMALIZED or Error
  * @retval    ECC_ERR_BAD_PARAMETER (P_pECPnt == NULL)
  */
int32_t ECCgetPointFlag(const ECpoint_stt *P_pECPnt);

/**
  * @brief Set the flag member of an Elliptic Curve Point structure (actually, do nothing in this implementation)
  * @param[in,out] *P_pECPnt The point whose flag will be set
  * @param[in]     P_newFlag The flag value to be set (ignored in this implementation)
  */
void ECCsetPointFlag(ECpoint_stt *P_pECPnt, ECPntFlags_et P_newFlag);

/**
  * @brief      Writes the Elliptic Curve Generator point into a ECpoint_stt
  * @param[out] *P_pPoint  The point    that will be set equal to the generator point
  * @param[in]  *P_pECctx  Structure    describing the curve parameters, it must contain the generator point
  * @retval    ECC_SUCCESS              Operation Successful
  * @retval    ECC_ERR_BAD_PARAMETER    One of the inputs == NULL
  * @retval    ECC_ERR_BAD_CONTEXT      Some values inside P_pECctx are invalid ( it doesn't contain the Generator )
  * @retval    MATH_ERR_BIGNUM_OVERFLOW The \c P_pPoint has not been initialized with the correct \c P_pECctx
  * @note      P_pPoint must be already initialized with \ref ECCinitPoint
  */
int32_t ECCsetPointGenerator(ECpoint_stt *P_pPoint, const EC_stt *P_pECctx);

/**
  * @brief      Copy an Elliptic Curve Point
  * @param[in]  *P_pOriginalPoint The point that will be copied
  * @param[out] *P_pCopyPoint     The output copy of P_OriginalPoint
  * @retval     ECC_SUCCESS Operation Successful
  * @retval     ECC_ERR_BAD_PARAMETER    One of the inputs is invalid (i.e. NULL or not initialized with ECCinitPoint)
  * @retval     MATH_ERR_BIGNUM_OVERFLOW The P_pCopyPoint has not been initialized with the correct P_pECctx
  * @note       Both points must be already initialized with \ref ECCinitPoint
  */
int32_t ECCcopyPoint(const ECpoint_stt *P_pOriginalPoint, ECpoint_stt *P_pCopyPoint);

/**
  * @brief      Initialize an ECC private key
  * @param[out]    **P_ppECCprivKey The private key that will be initialized
  * @param[in]     *P_pECctx        The \ref EC_stt containing the Elliptic Curve Parameters
  * @param[in,out] *P_pMemBuf       Pointer to the membuf_stt structure that will be used to
  *                                 store the Elliptic Curve Private Key internal value.
  * @retval        ECC_SUCCESS           Operation Successful
  * @retval        ECC_ERR_BAD_PARAMETER P_pECctx == NULL
  * @retval        ECC_ERR_BAD_CONTEXT   Some values inside P_pECctx are invalid
  * @retval        ERR_MEMORY_FAIL       There is no enough memory.
  * @note This function will keep some value stored in membuf_stt.pmBuf, therefore when exiting this function
  *       membuf_stt.mUsed will be greater than it was before the call.
  *       The memory will be freed when \ref ECCfreePrivKey will be called
  */
int32_t ECCinitPrivKey(ECCprivKey_stt **P_ppECCprivKey, const EC_stt *P_pECctx, membuf_stt *P_pMemBuf);

/**
  * @brief         Free an ECC Private Key
  * @param[in,out] **P_ppECCprivKey The private key that will be freed
  * @param[in,out] *P_pMemBuf       Pointer to the membuf_stt structure that currently stores
  *                                 the Elliptic Curve Private Key internal value
  * @retval        ECC_SUCCESS             Operation Successful
  * @retval        ECC_ERR_BAD_PARAMETER   P_ppECCprivKey == NULL || P_pMemBuf == NULL
  * @retval        ECC_ERR_BAD_PRIVATE_KEY Private Key uninitialized
  */
int32_t ECCfreePrivKey(ECCprivKey_stt **P_pECCprivKey, membuf_stt *P_pMemBuf);

/**
  * @brief         Set the value of an ECC private key object from a byte array
  * @param[in,out] *P_pECCprivKey   The ECC private key object to set
  * @param[in]     *P_pPrivateKey   Pointer to an uint8_t array that contains the value of the private key
  * @param[in]     P_privateKeySize The size in bytes of P_pPrivateKey
  * @retval        ECC_SUCCESS              Operation Successful
  * @retval        ECC_ERR_BAD_PRIVATE_KEY  Private Key uninitialized
  * @retval        ECC_ERR_BAD_PARAMETER    One of the input parameters is invalid
  * @retval        MATH_ERR_BIGNUM_OVERFLOW P_privateKeySize is too big for the allowed private key size
  */
int32_t ECCsetPrivKeyValue(ECCprivKey_stt *P_pECCprivKey, const uint8_t *P_pPrivateKey, int32_t P_privateKeySize);

/**
  * @brief  Get the private key value from an ECC private key object
  * @param[in]  *P_pECCprivKey     The ECC private key object to be retrieved
  * @param[out] *P_pPrivateKey     Pointer to an uint8_t array that will contain the value of the private key
  * @param[out] *P_pPrivateKeySize Pointer to an int that will contain the size in bytes of P_pPrivateKey
  * @retval     ECC_SUCCESS           Operation Successful
  * @retval     ECC_ERR_BAD_PARAMETER One of the input parameters is invalid
  * @retval     MATH_ERR_INTERNAL     Generic MATH error
  */
int32_t ECCgetPrivKeyValue(const ECCprivKey_stt *P_pECCprivKey, uint8_t *P_pPrivateKey, int32_t *P_pPrivateKeySize);

/**
  * @brief      Initialize an ECDSA signature structure
  * @param[out] **P_ppSignature Pointer to pointer to the ECDSA structure that will be allocated and initialized
  * @param[in]  *P_pECctx       The \ref EC_stt containing the Elliptic Curve Parameters
  * @param[in]  *P_pMemBuf      Pointer to the membuf_stt structure that will be used to
  *                             store the ECDSA signatures internal values
  * @retval     ECC_SUCCESS           Operation Successful
  * @retval     ECC_ERR_BAD_PARAMETER Invalid Parameter
  * @retval     ECC_ERR_BAD_CONTEXT   Some values inside P_pECctx or P_pMemBuf are invalid
  * @retval     ERR_MEMORY_FAIL       There is no enough memory.
  * @note This function will keep some value stored in membuf_stt.pmBuf, therefore when exiting this function
  *       membuf_stt.mUsed will be greater than it was before the call.
  *       The memory will be freed when \ref ECDSAfreeSign will be called
  */
int32_t ECDSAinitSign(ECDSAsignature_stt **P_ppSignature, const EC_stt *P_pECctx, membuf_stt *P_pMemBuf);

/**
  * @brief         Free an ECDSA signature structure
  * @param[in,out] **P_ppSignature The ECDSA signature that will be freed
  * @param[in,out] *P_pMemBuf      Pointer to the membuf_stt structure that currently stores
  *                                the ECDSA signature internal values
  * @retval        ECC_SUCCESS           Operation Successful
  * @retval        ECC_ERR_BAD_PARAMETER P_pSignature == NULL || P_pMemBuf == NULL
  */
int32_t ECDSAfreeSign(ECDSAsignature_stt **P_pSignature, membuf_stt *P_pMemBuf);

/**
  * @brief      Set the value of the parameters (one at a time) of an ECDSAsignature_stt
  * @param[out] *P_pSignature The ECDSA signature whose one of the value will be set
  * @param[in]  P_RorS        Flag used to select if the parameter R or the parameter S must be set
  * @param[in]  *P_pValue     Pointer to an uint8_t array containing the signature value
  * @param[in]  P_valueSize   Size of the signature value
  * @retval     ECC_SUCCESS              Operation Successful
  * @retval     ECC_ERR_BAD_PARAMETER    One of the input parameters is invalid
  * @retval     MATH_ERR_BIGNUM_OVERFLOW The signature value passed is too big for the Signature structure
  */
int32_t ECDSAsetSignature(ECDSAsignature_stt *P_pSignature,
                          ECDSAsignValues_et P_RorS,
                          const uint8_t      *P_pValue,
                          int32_t            P_valueSize);

/**
  * @brief     Get the values of the parameters (one at a time) of an ECDSAsignature_stt
  * @param[in]   *P_pSignature The ECDSA signature from which retrieve the value
  * @param[in]   P_RorS        Flag used to select if the parameter R or the parameter S must be returned
  * @param[out]  *P_pValue     Pointer to an uint8_t array that will contain the value
  * @param[out]  *P_pValueSize Pointer to an integer that will contain the size of the returned value
  * @retval      ECC_SUCCESS           Operation Successful
  * @retval      ECC_ERR_BAD_PARAMETER One of the input parameters is invalid
  * @retval      MATH_ERR_INTERNAL     Generic MATH error
  */
int32_t ECDSAgetSignature(const ECDSAsignature_stt *P_pSignature,
                          ECDSAsignValues_et       P_RorS,
                          uint8_t                  *P_pValue,
                          int32_t                  *P_pValueSize);

/**
  * @brief         Checks the validity of a public key
  * @param[in]     *P_pECCpubKey The public key to be checked
  * @param[in]     *P_pECctx     Structure describing the curve parameters
  * @param[in,out] *P_pMemBuf    Pointer to the membuf_stt structure that will be used to
  *                              store the internal values required by computation
  * @retval        ECC_SUCCESS                  P_pECCpubKey is a valid point of the curve
  * @retval        ECC_ERR_BAD_PUBLIC_KEY       P_pECCpubKey is not a valid point of the curve
  * @retval        ECC_ERR_BAD_PARAMETER        One of the input parameter is NULL
  * @retval        ECC_ERR_BAD_CONTEXT          One of the values inside P_pECctx is invalid
  * @retval        ECC_ERR_MISSING_EC_PARAMETER P_pECctx must contain a, p, n, b
  * @retval        ERR_MEMORY_FAIL              There is not enough memory.
  * @note This function does \b not check that PubKey * group_order == infinity_point.
  *       This is correct \b assuming that the curve's cofactor is 1
  */
int32_t ECCvalidatePubKey(const ECpoint_stt *pECCpubKey, const EC_stt *P_pECctx, membuf_stt *P_pMemBuf);

/**
  * @brief  Computes the point scalar multiplication kP = k*P
  * @param[in]     *P_pECbasePnt   The point that will be multiplied
  * @param[in]     *P_pECCprivKey  Structure containing the scalar value of the multiplication
  * @param[out]    *P_pECresultPnt The output point, result of the multiplication
  * @param[in]     *P_pECctx       Structure describing the curve parameters
  * @param[in,out] *P_pMemBuf      Pointer to the membuf_stt structure that currently stores
  *                                the Ellitpic Curve Private Key internal value
  * @retval        ECC_SUCCESS                  Operation Successful
  * @retval        ECC_ERR_BAD_PARAMETER        One of the inputs == NULL
  * @retval        ECC_ERR_BAD_CONTEXT          P_pECctx->pmInternalEC == NULL
  * @retval        ECC_ERR_MISSING_EC_PARAMETER Some required parameters are missing from the P_pECctx structure
  * @retval        ECC_ERR_BAD_PRIVATE_KEY      Private key (P_pECCprivKey) is not initialized or set
  * @retval        MATH_ERR_BIGNUM_OVERFLOW     ECCscalarMul has not been initialized with the correct P_pECctx
  * @retval        ERR_MEMORY_FAIL              There is no enough memory
  * @retval        ECC_WARN_POINT_AT_INFINITY   The returned point is the O point for the Elliptic Curve.
  * @retval        MATH_ERR_INTERNAL            Generic MATH error
  * @note \ref P_pECresultPnt must be already initialized, \ref P_pECCprivKey must be in range [1; N - 1]
  */
int32_t ECCscalarMul(const ECpoint_stt    *P_pECbasePnt,
                     const ECCprivKey_stt *P_pECCprivKey,
                     ECpoint_stt          *P_pECresultPnt,
                     const EC_stt         *P_pECctx,
                     membuf_stt           *P_pMemBuf);

/**
  * @brief      Generate an ECC key pair
  * @param[out]    *P_pPrivKey     Initialized object that will contain the generated private key
  * @param[out]    *P_pPubKey      Initialized point that will contain the generated public key
  * @param[in]     *P_pRandomState The random engine current state
  * @param[in]     *P_pECctx       Structure with the curve parameters, this must contain the values of the generator
  * @param[in,out] *P_pMemBuf      Pointer to the membuf_stt structure that will be used to store the
  *                                internal values required by computation
  * @retval  ECC_SUCCESS                  Key Pair generated successfully
  * @retval  ECC_ERR_BAD_CONTEXT          Some values inside P_pECctx are invalid
  * @retval  ECC_ERR_BAD_PARAMETER        One of input parameters is not valid
  * @retval  ECC_ERR_MISSING_EC_PARAMETER P_pECctx must contain a, p, n, Gx, Gy
  * @retval  MATH_ERR_BIGNUM_OVERFLOW     P_pPubKey has not been properly initialized
  * @retval  MATH_ERR_INTERNAL            Generic MATH error
  * @retval  RNG_ERR_UNINIT_STATE         Random engine not initialized.
  * @retval  RNG_ERR_INTERNAL             Internal RNG error
  * @retval  ERR_MEMORY_FAIL              There's not enough memory
  * @note  \ref P_pPrivKey and \ref P_pPubKey must be already initialized with respectively \ref ECCinitPrivKey
  *        and \ref ECCinitPoint; \ref P_pECctx must contain the value of the curve's generator
  */
int32_t ECCkeyGen(ECCprivKey_stt *P_pPrivKey,
                  ECpoint_stt    *P_pPubKey,
                  RNGstate_stt   *P_pRandomState,
                  const EC_stt   *P_pECctx,
                  membuf_stt     *P_pMemBuf);

/**
  * @brief         ECDSA Signature Generation
  * @param[in]     *P_pDigest    The message digest that will be signed
  * @param[in]     P_digestSize  The size in bytes of the P_pDigest
  * @param[out]    *P_pSignature Pointer to an initialized signature structure that will
  *                              be contain the result of the operation
  * @param[in]     *P_pSignCtx   Pointer to an initialized ECDSAsignCtx_stt structure
  * @param[in,out] *P_pMemBuf    Pointer to the membuf_stt structure that will be used to store the
  *                              internal values required by computation
  * @retval        ECC_SUCCESS                  Key Pair generated successfully
  * @retval        ECC_ERR_BAD_PARAMETER        One of input parameters is not valid
  * @retval        ECC_ERR_MISSING_EC_PARAMETER P_pECctx must contain a, p, n, Gx, Gy
  * @retval        ECC_ERR_BAD_CONTEXT          One of the values inside P_pSignCtx is invalid
  * @retval        RNG_ERR_UNINIT_STATE         Random engine not initialized.
  * @retval        RNG_ERR_INTERNAL             Internal RNG error
  * @retval        MATH_ERR_BIGNUM_OVERFLOW     Function context has not been initialized with the correct P_pECctx
  * @retval        MATH_ERR_INTERNAL            Generic MATH error
  * @retval        ERR_MEMORY_FAIL              There's not enough memory
  * @note This functions requires that:
  *       - \c P_pSignCtx.pmEC points to a valid and initialized \ref EC_stt structure
  *       - \c P_pSignCtx.pmPrivKey points to a valid and initialized private key \ref ECCprivKey_stt structure
  *       - \c P_pSignCtx.pmRNG  points to a valid and initialized Random State \ref RNGstate_stt structure
  */
int32_t ECDSAsign(const uint8_t            *P_pDigest,
                  int32_t                  P_digestSize,
                  const ECDSAsignature_stt *P_pSignature,
                  const ECDSAsignCtx_stt   *P_pSignCtx,
                  membuf_stt               *P_pMemBuf);

/**
  * @brief  ECDSA signature verification
  * @param[in]     *P_pDigest    The digest of the signed message
  * @param[in]     P_digestSize  The mSize in bytes of the digest
  * @param[in]     *P_pSignature The public key that will verify the signature
  * @param[in]     *P_pVerifyCtx The ECDSA signature context that will be verified
  * @param[in,out] *P_pMemBuf    Pointer to the membuf_stt structure that will be used to
  *                              store the internal values required by computation
  * @retval        ERR_MEMORY_FAIL              There's not enough memory
  * @retval        ECC_ERR_BAD_PARAMETER        One of the input parameters is NULL
  * @retval        ECC_ERR_BAD_CONTEXT          The values inside structures P_pSignature or P_pVerifyCtx are not
  *                                             properly initialized
  * @retval        ECC_ERR_MISSING_EC_PARAMETER Some required parameter is missing from  P_pVerifyCtx->pmEC
  * @retval        MATH_ERR_BIGNUM_OVERFLOW     Function context has not been initialized with the correct P_pECctx
  * @retval        MATH_ERR_INTERNAL            Generic MATH error
  * @retval        SIGNATURE_INVALID            Signature corrupted or not valid for the input digest and public key
  * @retval        SIGNATURE_VALID              Signature correctly verified
  * @note This functions requires that:
  *       - \c P_pVerifyCtx.pmEC points to a valid and initialized \ref EC_stt structure
  *       - \c P_pVerifyCtx.pmPubKey points to a valid and initialized public key \ref ECpoint_stt structure
  */
int32_t ECDSAverify(const uint8_t            *P_pDigest,
                    int32_t                  P_digestSize,
                    const ECDSAsignature_stt *P_pSignature,
                    const ECDSAverifyCtx_stt *P_pVerifyCtx,
                    membuf_stt               *P_pMemBuf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CMOX_HELPER_ECC_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
