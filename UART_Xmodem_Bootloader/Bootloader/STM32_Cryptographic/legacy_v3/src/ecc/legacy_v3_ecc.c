/**
  ******************************************************************************
  * @file    legacy_v3_ecc.c
  * @author  MCD Application Team
  * @brief   This file provides ECDSA/ECDH functions of helper for
  *          migration of cryptographics library V3 to V4
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

#include "drbg/legacy_v3_ctr_drbg.h"
#include "ecc/cmox_ecdsa.h"
#include "ecc/cmox_ecdh.h"
#include "ecc/cmox_ecc_custom_curves.h"
#include "ecc/legacy_v3_ecc.h"
#include "membuf/legacy_v3_membuf_internal.h"
#include "err_codes.h"
#include <string.h>

#ifndef MAX
#define MAX(a,b) (((a) > (b)) ? (a) : (b)) /*!< Macro to determine the maximum between two elements */
#endif /* MAX */

/* Private API */

/* Compute the bit length of a 32-bit integer */
static uint8_t bitLength(uint8_t x)
{
  uint8_t i; /* iterator counter */
  uint8_t bl = 8u; /* length counter, decreased if leading 0 found */
  uint8_t search = 1u; /* temporary var for constant time implementation */
  /* loop over all the word bits, not skipping the most significant zeros */
  for (i = 7u; i < 0xFFu; i--)
  {
    search &= ((x >> i) & 1u) ^ 1u; /* if search becomes 0, it will never be 1 again */
    bl -= search; /* decrease while search is 1, that is a 1 still not found */
  }
  return bl;
}

/**
  * @brief Convert CLV4 results into CLv3 results
  * @param[in]  cmox_rv  Result of a CLv4 API
  * @return CLv3 rturn value correspondent to the input one
  */
static int32_t cmox_helper_ecc_rv_convert(cmox_ecc_retval_t cmox_rv)
{
  int32_t rv;

  /* Following CMOX retvals should not happen:
   * - CMOX_ECC_ERR_WRONG_RANDOM: we cycle over drbg generation untile this doesn't happen anymore
   * - CMOX_ECC_ERR_MATHCURVE_MISMATCH: used math is always compatible
   * - CMOX_ECC_ERR_ALGOCURVE_MISMATCH: custom curve is always compatible for ECDSA/ECDH
   * - CMOX_ECC_ERR_INTERNAL: used only in EDDSA, that is not part of this section
   * Following CLv3 retvals will not never be outputted:
   * - ECC_ERR_MISSING_EC_PARAMETER
   * - ECC_WARN_POINT_AT_INFINITY
   */
  switch (cmox_rv)
  {
    case CMOX_ECC_SUCCESS: /* everything ok */
      rv = ECC_SUCCESS;
      break;
    case CMOX_ECC_AUTH_SUCCESS: /* verification pass */
      rv = SIGNATURE_VALID;
      break;
    case CMOX_ECC_AUTH_FAIL: /* verification fail */
    case CMOX_ECC_ERR_INVALID_SIGNATURE: /* invalid/bad formatted signature */
      rv = SIGNATURE_INVALID;
      break;
    case CMOX_ECC_ERR_INVALID_PUBKEY: /* invalid/bad formatted public key */
      rv = ECC_ERR_BAD_PUBLIC_KEY;
      break;
    case CMOX_ECC_ERR_MEMORY_FAIL: /* not enough memory */
      rv = ERR_MEMORY_FAIL;
      break;
    default: /* CMOX_ECC_ERR_BAD_PARAMETERS */
      rv = ECC_ERR_BAD_PARAMETER;
      break;
  }

  return rv;
}

/* Public API */

/* Initialize the elliptic curve parameters into a EC_stt structure */
int32_t ECCinitEC(EC_stt *P_pECctx, membuf_stt *P_pMemBuf)
{
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */

  /* initialize the math engine and the memory buffer */
  cmox_ecc_construct(&(P_pECctx->cmox_ctx), CMOX_MATH_FUNCS_SMALL,
                     &(P_pMemBuf->pmBuf[P_pMemBuf->mUsed]), (size_t)P_pMemBuf->mSize - (size_t)P_pMemBuf->mUsed);

  /* build the custom curve from user parameters */
  cmox_rv = cmox_ecc_customCurveConstruct(&(P_pECctx->cmox_ctx),
                                          &(P_pECctx->pmInternalEC),
                                          cmox_ecc_customCurve_opt_low,
                                          P_pECctx->pmP, P_pECctx->mPsize, /* P */
                                          P_pECctx->pmN, P_pECctx->mNsize, /* N */
                                          P_pECctx->pmA, P_pECctx->mAsize, /* A */
                                          P_pECctx->pmB, P_pECctx->mBsize, /* B */
                                          P_pECctx->pmGx, P_pECctx->mGxsize, /* Gx */
                                          P_pECctx->pmGy, P_pECctx->mGysize); /* Gy */
  /* synchronize CLv3 membuf from CLv4 membuf */
  cmox_helper_membuf_fromV4(&(P_pECctx->cmox_ctx.membuf_str), P_pMemBuf);

  /* return proper return value */
  return cmox_helper_ecc_rv_convert(cmox_rv);
}

/* De-initialize an EC_stt context */
int32_t ECCfreeEC(EC_stt *P_pECctx, membuf_stt *P_pMemBuf)
{
  /* destroy the custom curve structure */
  cmox_ecc_customCurveCleanup(&(P_pECctx->cmox_ctx), &(P_pECctx->pmInternalEC));
  /* synchronize CLv3 membuf from CLv4 membuf */
  cmox_helper_membuf_fromV4(&(P_pECctx->cmox_ctx.membuf_str), P_pMemBuf);
  /* destroy ecc context */
  cmox_ecc_cleanup(&(P_pECctx->cmox_ctx));

  /* return proper return value */
  return ECC_SUCCESS;
}

/* Initialize an ECC point */
int32_t ECCinitPoint(ECpoint_stt **P_ppECPnt, const EC_stt *P_pECctx, membuf_stt *P_pMemBuf)
{
  int32_t rv;
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */

  /* check for NULL/wrong input parameters */
  if ((P_pECctx == NULL) || (P_pMemBuf == NULL) || (P_ppECPnt == NULL))
  {
    rv = ECC_ERR_BAD_PARAMETER;
  }
  else if (P_pECctx->pmInternalEC == NULL)
  {
    rv = ECC_ERR_BAD_CONTEXT;
  }
  else
  {
    /* allocate point structure */
    cmox_rv = clv3_allocate(P_pMemBuf, (uint8_t **)P_ppECPnt, (uint16_t)sizeof(ECpoint_stt));
    if (cmox_rv != 0u)
    {
      rv = ERR_MEMORY_FAIL;
    }
    else
    {
      /* allocate point byte buffer */
      cmox_rv = clv3_allocate(P_pMemBuf, &((*P_ppECPnt)->pPoint), 2u * (uint16_t)P_pECctx->mPsize);
      if (cmox_rv != 0u)
      {
        (void)clv3_free(P_pMemBuf, (uint8_t **)P_ppECPnt, (uint16_t)sizeof(ECpoint_stt)); /* free the prev allocated */
        rv = ERR_MEMORY_FAIL;
      }
      else
      {
        (*P_ppECPnt)->pCurve = P_pECctx; /* set the internal curve pointer to link the curve */
        rv = ECC_SUCCESS;
      }
    }

    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pECctx->cmox_ctx.membuf_str));
  }

  return rv; /* return proper return value */
}

/* Free Elliptic curve point */
int32_t ECCfreePoint(ECpoint_stt **P_ppECPnt, membuf_stt *P_pMemBuf)
{
  int32_t rv;
  cmox_membuf_handle_st *v4_membuf_ptr = NULL;

  /* check for NULL/wrong input parameters */
  if (P_ppECPnt == NULL)
  {
    rv = ECC_ERR_BAD_PARAMETER;
  }
  else if ((*P_ppECPnt == NULL) || ((*P_ppECPnt)->pPoint == NULL) || ((*P_ppECPnt)->pCurve == NULL))
  {
    rv = ECC_ERR_BAD_CONTEXT;
  }
  else
  {
    v4_membuf_ptr = (cmox_membuf_handle_st *) & ((*P_ppECPnt)->pCurve->cmox_ctx.membuf_str);

    /* free point byte buffer */
    (void)clv3_free(P_pMemBuf, &((*P_ppECPnt)->pPoint), 2u * (uint16_t)((*P_ppECPnt)->pCurve->mPsize));
    /* free point structure */
    (void)clv3_free(P_pMemBuf, (uint8_t **)P_ppECPnt, (uint16_t)sizeof(ECpoint_stt));

    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, v4_membuf_ptr);

    rv = ECC_SUCCESS; /* return proper return value */
  }

  return rv;
}

/* Set the value of one of coordinate of an ECC point */
int32_t ECCsetPointCoordinate(ECpoint_stt     *P_pECPnt,
                              ECcoordinate_et P_Coordinate,
                              const uint8_t   *P_pCoordinateValue,
                              int32_t         P_coordinateSize)
{
  int32_t retval = ECC_ERR_BAD_PARAMETER;

  /* check for NULL/wrong input parameters */
  if ((P_pECPnt != NULL) && (P_pECPnt->pPoint != NULL) && (P_pCoordinateValue != NULL) && (P_coordinateSize >= 0)
      && ((int32_t)(P_pECPnt->pCurve->mPsize) >= P_coordinateSize))
  {
    switch (P_Coordinate)
    {
      case E_ECC_POINT_COORDINATE_X:
        /* copy the coordinate to the least significant bytes of the output buffer */
        (void)memcpy(&P_pECPnt->pPoint[P_pECPnt->pCurve->mPsize - (uint32_t)P_coordinateSize], P_pCoordinateValue,
                     (size_t)P_coordinateSize);
        /* set most significant bytes, if any, to zero */
        (void)memset(P_pECPnt->pPoint, 0, (size_t)P_pECPnt->pCurve->mPsize - (size_t)P_coordinateSize);
        retval = ECC_SUCCESS;
        break;
      case E_ECC_POINT_COORDINATE_Y:
        /* copy the coordinate to the least significant bytes of the output buffer */
        (void)memcpy(&P_pECPnt->pPoint[(2u * P_pECPnt->pCurve->mPsize) - (uint32_t)P_coordinateSize],
                     P_pCoordinateValue, (size_t)P_coordinateSize);
        /* set most significant bytes, if any, to zero */
        (void)memset(&P_pECPnt->pPoint[P_pECPnt->pCurve->mPsize], 0,
                     (size_t)P_pECPnt->pCurve->mPsize - (size_t)P_coordinateSize);
        retval = ECC_SUCCESS;
        break;
      default: /* Z coordinate not used in this implementation */
        retval = ECC_ERR_BAD_PARAMETER;
        break;
    }
  }

  /* return proper return value */
  return retval;
}

/* Get the value of one of coordinate of an ECC point */
int32_t ECCgetPointCoordinate(const ECpoint_stt *P_pECPnt,
                              ECcoordinate_et   P_Coordinate,
                              uint8_t           *P_pCoordinateValue,
                              int32_t           *P_pCoordinateSize)
{
  int32_t retval = ECC_ERR_BAD_PARAMETER;

  /* check for NULL/wrong input parameters */
  if ((P_pECPnt != NULL) && (P_pECPnt->pPoint != NULL) && (P_pCoordinateValue != NULL))
  {
    switch (P_Coordinate)
    {
      case E_ECC_POINT_COORDINATE_X:
        /* copy the first half of the buffer in the output buffer */
        (void)memcpy(P_pCoordinateValue, P_pECPnt->pPoint, (size_t)P_pECPnt->pCurve->mPsize);
        retval = ECC_SUCCESS;
        break;
      case E_ECC_POINT_COORDINATE_Y:
        /* copy the second half of the buffer in the output buffer */
        (void)memcpy(P_pCoordinateValue, &P_pECPnt->pPoint[P_pECPnt->pCurve->mPsize], (size_t)P_pECPnt->pCurve->mPsize);
        retval = ECC_SUCCESS;
        break;
      default: /* Z coordinate not used in this implementation */
        retval = ECC_ERR_BAD_PARAMETER;
        break;
    }
    /* if length input param is provided, set it with the output length */
    if (P_pCoordinateSize != NULL)
    {
      *P_pCoordinateSize = (int32_t)P_pECPnt->pCurve->mPsize;
    }
  }

  /* return proper return value */
  return retval;
}

/* Returns the point flag (actually only \ref E_POINT_NORMALIZED is used in this implementation) */
int32_t ECCgetPointFlag(const ECpoint_stt *P_pECPnt)
{
  int32_t rv = ECC_ERR_BAD_PARAMETER;

  /* check for NULL/wrong input parameters */
  if (P_pECPnt != NULL)
  {
    rv = (int32_t)E_POINT_NORMALIZED;
  }

  return rv; /* return proper return value */
}

/* Set the flag member of an Elliptic Curve Point structure (actually, do nothing in this implementation) */
void ECCsetPointFlag(ECpoint_stt *P_pECPnt, ECPntFlags_et P_newFlag)
{
  (void)P_pECPnt; /* point pointer not used */
  (void)P_newFlag; /* new flag not set, because useless */
  /* do nothing, flag can be only E_POINT_NORMALIZED */
}

/* Writes the Elliptic Curve Generator point into a ECpoint_stt */
int32_t ECCsetPointGenerator(ECpoint_stt *P_pPoint, const EC_stt *P_pECctx)
{
  int32_t retval = ECC_ERR_BAD_PARAMETER;

  /* check for NULL/wrong input parameters */
  if ((P_pPoint != NULL) && (P_pPoint->pPoint != NULL) && (P_pECctx != NULL)
      && (P_pPoint->pCurve->mPsize >= P_pECctx->mPsize))
  {
    /* we use param P_pECctx, but we could use P_pPoint->pCurve: they should be the same */

    /* copy the X to the least significant bytes of the first half of the buffer */
    (void)memcpy(&P_pPoint->pPoint[P_pPoint->pCurve->mPsize - P_pECctx->mGxsize], P_pECctx->pmGx,
                 (size_t)P_pECctx->mGxsize);
    /* set most significant bytes, if any, to zero */
    (void)memset(P_pPoint->pPoint, 0, (size_t)P_pPoint->pCurve->mPsize - (size_t)P_pECctx->mGxsize);

    /* copy the Y to the least significant bytes of the second half of the buffer */
    (void)memcpy(&P_pPoint->pPoint[(2u * P_pPoint->pCurve->mPsize) - P_pECctx->mGysize], P_pECctx->pmGy,
                 (size_t)P_pECctx->mGysize);
    /* set most significant bytes, if any, to zero */
    (void)memset(&P_pPoint->pPoint[P_pPoint->pCurve->mPsize], 0,
                 (size_t)P_pPoint->pCurve->mPsize - (size_t)P_pECctx->mGysize);

    /* return proper return value */
    retval = ECC_SUCCESS;
  }

  return retval;
}

/* Copy an Elliptic Curve Point */
int32_t ECCcopyPoint(const ECpoint_stt *P_pOriginalPoint, ECpoint_stt *P_pCopyPoint)
{
  int32_t retval = ECC_ERR_BAD_PARAMETER;

  /* check for NULL/wrong input parameters */
  if ((P_pOriginalPoint != NULL) && (P_pOriginalPoint->pPoint != NULL)
      && (P_pCopyPoint != NULL) && (P_pCopyPoint->pPoint != NULL))
  {
    /* copy the byte buffer */
    (void)memcpy(P_pCopyPoint->pPoint, P_pOriginalPoint->pPoint, 2u * (size_t)P_pOriginalPoint->pCurve->mPsize);
    /* set the curve pointer */
    P_pCopyPoint->pCurve = P_pOriginalPoint->pCurve;

    retval = ECC_SUCCESS; /* return proper return value */
  }

  return retval;
}

/*  Initialize an ECC private key */
int32_t ECCinitPrivKey(ECCprivKey_stt **P_ppECCprivKey, const EC_stt *P_pECctx, membuf_stt *P_pMemBuf)
{
  int32_t rv;
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */

  /* check for NULL/wrong input parameters */
  if ((P_pECctx == NULL) || (P_pMemBuf == NULL) || (P_ppECCprivKey == NULL))
  {
    rv = ECC_ERR_BAD_PARAMETER;
  }
  else if (P_pECctx->pmInternalEC == NULL)
  {
    rv = ECC_ERR_BAD_CONTEXT;
  }
  else
  {
    /* allocate Private Key structure */
    cmox_rv = clv3_allocate(P_pMemBuf, (uint8_t **)P_ppECCprivKey, (uint16_t)sizeof(ECCprivKey_stt));
    if (cmox_rv != 0u)
    {
      rv = ERR_MEMORY_FAIL;
    }
    else
    {
      /* allocate Private Key byte buffer */
      cmox_rv = clv3_allocate(P_pMemBuf, &((*P_ppECCprivKey)->pD), (uint16_t)P_pECctx->mNsize);
      if (cmox_rv != 0u)
      {
        (void)clv3_free(P_pMemBuf, (uint8_t **)P_ppECCprivKey, (uint16_t)sizeof(ECCprivKey_stt)); /* free the prev */
        rv = ERR_MEMORY_FAIL;
      }
      else
      {
        (*P_ppECCprivKey)->pCurve = P_pECctx; /* set the internal curve pointer to link the curve */
        rv = ECC_SUCCESS; /* return proper return value */
      }
    }

    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pECctx->cmox_ctx.membuf_str));
  }

  return rv;
}

/* Free an ECC Private Key */
int32_t ECCfreePrivKey(ECCprivKey_stt **P_pECCprivKey, membuf_stt *P_pMemBuf)
{
  int32_t rv;
  cmox_membuf_handle_st *v4_membuf_ptr = NULL;

  /* check for NULL/wrong input parameters */
  if (P_pECCprivKey == NULL)
  {
    rv = ECC_ERR_BAD_PARAMETER;
  }
  else if ((*P_pECCprivKey == NULL) || ((*P_pECCprivKey)->pD == NULL) || ((*P_pECCprivKey)->pCurve == NULL))
  {
    rv = ECC_ERR_BAD_PRIVATE_KEY;
  }
  else
  {
    /* get CLv4 membuf pointer */
    v4_membuf_ptr = (cmox_membuf_handle_st *) & ((*P_pECCprivKey)->pCurve->cmox_ctx.membuf_str);

    /* free Private Key byte buffer */
    (void)clv3_free(P_pMemBuf, &((*P_pECCprivKey)->pD), (uint16_t)(*P_pECCprivKey)->pCurve->mNsize);
    /* free Private Key structure */
    (void)clv3_free(P_pMemBuf, (uint8_t **)P_pECCprivKey, (uint16_t)sizeof(ECCprivKey_stt));

    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, v4_membuf_ptr);

    rv = ECC_SUCCESS; /* return proper return value */
  }

  return rv;
}

/* Set the value of an ECC private key object from a byte array */
int32_t ECCsetPrivKeyValue(ECCprivKey_stt *P_pECCprivKey, const uint8_t *P_pPrivateKey, int32_t P_privateKeySize)
{
  int32_t retval = ECC_ERR_BAD_PRIVATE_KEY;

  /* check for NULL/wrong input parameters */
  if ((P_pECCprivKey != NULL) && (P_pECCprivKey->pD != NULL) && (P_pPrivateKey != NULL) && (P_privateKeySize >= 0)
      && ((int32_t)(P_pECCprivKey->pCurve->mNsize) >= P_privateKeySize))
  {
    /* copy the provided private key to the least significant bytes of the internal buffer */
    (void)memcpy(&P_pECCprivKey->pD[P_pECCprivKey->pCurve->mNsize - (uint32_t)P_privateKeySize], P_pPrivateKey,
                 (size_t)P_privateKeySize);
    /* set most significant bytes, if any, to zero */
    (void)memset(P_pECCprivKey->pD, 0, (size_t)P_pECCprivKey->pCurve->mNsize - (size_t)P_privateKeySize);
    /* return proper return value */
    retval = ECC_SUCCESS;
  }

  return retval;
}

/* Get the private key value from an ECC private key object */
int32_t ECCgetPrivKeyValue(const ECCprivKey_stt *P_pECCprivKey, uint8_t *P_pPrivateKey, int32_t *P_pPrivateKeySize)
{
  int32_t retval = ECC_ERR_BAD_PARAMETER;

  /* check for NULL/wrong input parameters */
  if ((P_pECCprivKey != NULL) && (P_pECCprivKey->pD != NULL) && (P_pPrivateKey != NULL))
  {
    /* copy the internal private key to the output buffer */
    (void)memcpy(P_pPrivateKey, P_pECCprivKey->pD, P_pECCprivKey->pCurve->mNsize);
    /* if length input param is provided, set it with the output length */
    if (P_pPrivateKeySize != NULL)
    {
      *P_pPrivateKeySize = (int32_t)P_pECCprivKey->pCurve->mNsize;
    }
    /* return proper return value */
    retval = ECC_SUCCESS;
  }

  return retval;
}

/* Initialize an ECDSA signature structure */
int32_t ECDSAinitSign(ECDSAsignature_stt **P_ppSignature, const EC_stt *P_pECctx, membuf_stt *P_pMemBuf)
{
  int32_t rv;
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */

  /* check for NULL/wrong input parameters */
  if ((P_pECctx == NULL) || (P_pMemBuf == NULL) || (P_ppSignature == NULL))
  {
    rv = ECC_ERR_BAD_PARAMETER;
  }
  else if (P_pECctx->pmInternalEC == NULL)
  {
    rv = ECC_ERR_BAD_CONTEXT;
  }
  else
  {
    /* allocate signature structure */
    cmox_rv = clv3_allocate(P_pMemBuf, (uint8_t **)P_ppSignature, (uint16_t)sizeof(ECDSAsignature_stt));
    if (cmox_rv != 0u)
    {
      rv = ERR_MEMORY_FAIL;
    }
    else
    {
      /* allocate signature byte buffer */
      cmox_rv = clv3_allocate(P_pMemBuf, &((*P_ppSignature)->pSig), 2u * (uint16_t)P_pECctx->mNsize);
      if (cmox_rv != 0u)
      {
        (void)clv3_free(P_pMemBuf, (uint8_t **)P_ppSignature,
                        (uint16_t)sizeof(ECDSAsignature_stt)); /* free the one correctly allocated */
        rv = ERR_MEMORY_FAIL;
      }
      else
      {
        (*P_ppSignature)->pCurve = P_pECctx; /* set the internal curve pointer to link the curve */
        rv = ECC_SUCCESS; /* return proper return value */
      }
    }

    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pECctx->cmox_ctx.membuf_str));
  }

  return rv;
}

/* Free an ECDSA signature structure */
int32_t ECDSAfreeSign(ECDSAsignature_stt **P_pSignature, membuf_stt *P_pMemBuf)
{
  int32_t rv;
  cmox_membuf_handle_st *v4_membuf_ptr = NULL;

  /* check for NULL/wrong input parameters */
  if (P_pSignature == NULL)
  {
    rv = ECC_ERR_BAD_PARAMETER;
  }
  else if ((*P_pSignature == NULL) || ((*P_pSignature)->pSig == NULL) || ((*P_pSignature)->pCurve == NULL))
  {
    rv = ECC_ERR_BAD_CONTEXT;
  }
  else
  {
    /* get CLv4 membuf pointer */
    v4_membuf_ptr = (cmox_membuf_handle_st *) & ((*P_pSignature)->pCurve->cmox_ctx.membuf_str);

    /* free signature byte buffer */
    (void)clv3_free(P_pMemBuf, &((*P_pSignature)->pSig), 2u * (uint16_t)(*P_pSignature)->pCurve->mNsize);
    /* free signature structure */
    (void)clv3_free(P_pMemBuf, (uint8_t **)P_pSignature, (uint16_t)sizeof(ECDSAsignature_stt));

    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, v4_membuf_ptr);

    /* return proper return value */
    rv = ECC_SUCCESS;
  }

  return rv;
}

/* Set the value of the parameters (one at a time) of an ECDSAsignature_stt */
int32_t ECDSAsetSignature(ECDSAsignature_stt *P_pSignature,
                          ECDSAsignValues_et P_RorS,
                          const uint8_t      *P_pValue,
                          int32_t            P_valueSize)
{
  int32_t retval = ECC_ERR_BAD_PARAMETER;

  /* check for NULL/wrong input parameters */
  if ((P_pSignature != NULL) && (P_pSignature->pSig != NULL) && (P_pValue != NULL) && (P_valueSize >= 0)
      && ((int32_t)(P_pSignature->pCurve->mNsize) >= P_valueSize))
  {
    switch (P_RorS)
    {
      case E_ECDSA_SIGNATURE_R_VALUE:
        /* copy the signature to the least significant bytes of the output buffer */
        (void)memcpy(&P_pSignature->pSig[P_pSignature->pCurve->mNsize - (uint32_t)P_valueSize], P_pValue,
                     (size_t)P_valueSize);
        /* set most significant bytes, if any, to zero */
        (void)memset(P_pSignature->pSig, 0, (size_t)P_pSignature->pCurve->mNsize - (size_t)P_valueSize);
        retval = ECC_SUCCESS;
        break;
      case E_ECDSA_SIGNATURE_S_VALUE:
        /* copy the signature to the least significant bytes of the output buffer */
        (void)memcpy(&P_pSignature->pSig[(2u * P_pSignature->pCurve->mNsize) - (uint32_t)P_valueSize], P_pValue,
                     (size_t)P_valueSize);
        /* set most significant bytes, if any, to zero */
        (void)memset(&P_pSignature->pSig[P_pSignature->pCurve->mNsize], 0,
                     (size_t)P_pSignature->pCurve->mNsize - (size_t)P_valueSize);
        retval = ECC_SUCCESS;
        break;
      default: /* no other value possible */
        retval = ECC_ERR_BAD_PARAMETER;
        break;
    }
  }

  /* return proper return value */
  return retval;
}

/* Get the values of the parameters (one at a time) of an ECDSAsignature_stt */
int32_t ECDSAgetSignature(const ECDSAsignature_stt *P_pSignature,
                          ECDSAsignValues_et       P_RorS,
                          uint8_t                  *P_pValue,
                          int32_t                  *P_pValueSize)
{
  int32_t retval = ECC_ERR_BAD_PARAMETER;

  /* check for NULL/wrong input parameters */
  if ((P_pSignature != NULL) && (P_pValue != NULL) && (P_pSignature->pSig != NULL))
  {
    switch (P_RorS)
    {
      case E_ECDSA_SIGNATURE_R_VALUE:
        /* copy the first half of the buffer in the output buffer */
        (void)memcpy(P_pValue, P_pSignature->pSig, (size_t)P_pSignature->pCurve->mNsize);
        retval = ECC_SUCCESS;
        break;
      case E_ECDSA_SIGNATURE_S_VALUE:
        /* copy the second half of the buffer in the output buffer */
        (void)memcpy(P_pValue, &P_pSignature->pSig[P_pSignature->pCurve->mNsize], (size_t)P_pSignature->pCurve->mNsize);
        retval = ECC_SUCCESS;
        break;
      default: /* no other value possible */
        retval = ECC_ERR_BAD_PARAMETER;
        break;
    }
    /* if length input param is provided, set it with the output length */
    if (P_pValueSize != NULL)
    {
      *P_pValueSize = (int32_t)(P_pSignature->pCurve->mNsize);
    }
  }

  /* return proper return value */
  return retval;
}

/* Main API */

/* Checks the validity of a public key */
int32_t ECCvalidatePubKey(const ECpoint_stt *pECCpubKey, const EC_stt *P_pECctx, membuf_stt *P_pMemBuf)
{
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */
  uint8_t *fake_res_point_and_sk;

  /* allocate memory for the ECDH result (in case the public key is valid) and the fake private key */
  cmox_rv = clv3_allocate(P_pMemBuf, &fake_res_point_and_sk,
                          2u * MAX((uint16_t)P_pECctx->mPsize, (uint16_t)P_pECctx->mNsize));
  if (cmox_rv == 0u)
  {
    /* set the private key to 1, avoiding uninitialized data warning and having a valid private key */
    memset(fake_res_point_and_sk, 0, (size_t)P_pECctx->mNsize);
    fake_res_point_and_sk[0u] = 1u;

    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pECctx->cmox_ctx.membuf_str));

    /* perform scalar multiplication with CLv4 key exchange */
    cmox_rv = cmox_ecdh((cmox_ecc_handle_t *) & (P_pECctx->cmox_ctx), P_pECctx->pmInternalEC,
                        fake_res_point_and_sk, (size_t)P_pECctx->mNsize,
                        pECCpubKey->pPoint, 2u * (size_t)pECCpubKey->pCurve->mPsize,
                        fake_res_point_and_sk, NULL);

    /* free the fake ECDH result */
    (void)clv3_free(P_pMemBuf, &fake_res_point_and_sk, 2u * (uint16_t)P_pECctx->mPsize);
  }

  /* return proper return value */
  return cmox_helper_ecc_rv_convert(cmox_rv);
}

/* Computes the point scalar multiplication kP = k*P */
int32_t ECCscalarMul(const ECpoint_stt    *P_pECbasePnt,
                     const ECCprivKey_stt *P_pECCprivKey,
                     ECpoint_stt          *P_pECresultPnt,
                     const EC_stt         *P_pECctx,
                     membuf_stt           *P_pMemBuf)
{
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */

  /* synchronize CLv3 membuf to CLv4 membuf */
  cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pECctx->cmox_ctx.membuf_str));

  /* perform scalar multiplication with CLv4 key exchange */
  cmox_rv = cmox_ecdh((cmox_ecc_handle_t *) & (P_pECctx->cmox_ctx), P_pECctx->pmInternalEC,
                      P_pECCprivKey->pD, P_pECCprivKey->pCurve->mNsize,
                      P_pECbasePnt->pPoint, 2u * (size_t)P_pECbasePnt->pCurve->mPsize,
                      P_pECresultPnt->pPoint, NULL);

  /* return proper return value */
  return cmox_helper_ecc_rv_convert(cmox_rv);
}

/* Generate an ECC key pair */
int32_t ECCkeyGen(ECCprivKey_stt *P_pPrivKey,
                  ECpoint_stt    *P_pPubKey,
                  RNGstate_stt   *P_pRandomState,
                  const EC_stt   *P_pECctx,
                  membuf_stt     *P_pMemBuf)
{
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */
  uint8_t *k;
  int32_t retval;
  uint8_t bitlen;

  /* allocate memory for the random buffer to generate */
  cmox_rv = clv3_allocate(P_pMemBuf, &k, (uint16_t)P_pECctx->mNsize);
  if (cmox_rv == 0u)
  {
    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pECctx->cmox_ctx.membuf_str));

    /* generate random until it's valid for ECDSA signing function */
    do
    {
      /* generate a random number of the same BYTElength of N */
      retval = RNGgenBytes(P_pRandomState, NULL, k, (int32_t)P_pECctx->mNsize);
      if (retval != 0)
      {
        cmox_rv = CMOX_ECC_ERR_BAD_PARAMETERS;
      }
      else
      {
        /* make the random number with the same BITlength of N */
        bitlen = bitLength(P_pECctx->pmN[0]) & 7u;
        if (bitlen != 0u) /* this branch is done on a public value: no timing attacks possible */
        {
          k[0] &= (0xFFu >> (8u - bitlen));
        }

        /* call the ECDSA sign function */
        cmox_rv = cmox_ecdsa_keyGen((cmox_ecc_handle_t *) & (P_pECctx->cmox_ctx), P_pECctx->pmInternalEC,
                                    k, P_pECctx->mNsize,
                                    P_pPrivKey->pD, NULL,
                                    P_pPubKey->pPoint, NULL);
      }
    } while (cmox_rv == CMOX_ECC_ERR_WRONG_RANDOM);

    /* free k */
    (void)clv3_free(P_pMemBuf, &k, (uint16_t)P_pECctx->mNsize);

    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pECctx->cmox_ctx.membuf_str));
  }
  else
  {
    cmox_rv = CMOX_ECC_ERR_MEMORY_FAIL;
  }

  /* return proper return value */
  return cmox_helper_ecc_rv_convert(cmox_rv);
}

/* ECDSA Signature Generation */
int32_t ECDSAsign(const uint8_t            *P_pDigest,
                  int32_t                  P_digestSize,
                  const ECDSAsignature_stt *P_pSignature,
                  const ECDSAsignCtx_stt   *P_pSignCtx,
                  membuf_stt               *P_pMemBuf)
{
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */
  uint8_t *k;
  int32_t retval;
  uint8_t bitlen;

  /* allocate memory for the random buffer to generate */
  cmox_rv = clv3_allocate(P_pMemBuf, &k, (uint16_t)P_pSignCtx->pmEC->mNsize);
  if (cmox_rv == 0u)
  {
    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pSignCtx->pmEC->cmox_ctx.membuf_str));

    /* generate random until it's valid for ECDSA signing function */
    do
    {
      /* generate a random number of the same BYTElength of N */
      retval = RNGgenBytes(P_pSignCtx->pmRNG, NULL, k, (int32_t)P_pSignCtx->pmEC->mNsize);
      if (retval != 0)
      {
        cmox_rv = CMOX_ECC_ERR_BAD_PARAMETERS;
      }
      else
      {
        /* make the random number with the same BITlength of N */
        bitlen = bitLength(P_pSignCtx->pmEC->pmN[0]) & 7u;
        if (bitlen != 0u) /* this branch is done on a public value: no timing attacks possible */
        {
          k[0] &= (0xFFu >> (8u - bitlen));
        }

        /* call the ECDSA sign function */
        cmox_rv = cmox_ecdsa_sign((cmox_ecc_handle_t *) & (P_pSignCtx->pmEC->cmox_ctx), P_pSignCtx->pmEC->pmInternalEC,
                                  k, P_pSignCtx->pmEC->mNsize,
                                  P_pSignCtx->pmPrivKey->pD, P_pSignCtx->pmPrivKey->pCurve->mNsize,
                                  P_pDigest, (size_t)P_digestSize,
                                  P_pSignature->pSig, NULL);
      }
    } while (cmox_rv == CMOX_ECC_ERR_WRONG_RANDOM);

    /* free k */
    (void)clv3_free(P_pMemBuf, &k, (uint16_t)P_pSignCtx->pmEC->mNsize);

    /* synchronize CLv3 membuf to CLv4 membuf */
    cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pSignCtx->pmEC->cmox_ctx.membuf_str));
  }
  else
  {
    cmox_rv = CMOX_ECC_ERR_MEMORY_FAIL;
  }

  /* return proper return value */
  return cmox_helper_ecc_rv_convert(cmox_rv);
}

/* ECDSA signature verification */
int32_t ECDSAverify(const uint8_t            *P_pDigest,
                    int32_t                  P_digestSize,
                    const ECDSAsignature_stt *P_pSignature,
                    const ECDSAverifyCtx_stt *P_pVerifyCtx,
                    membuf_stt               *P_pMemBuf)
{
  cmox_ecc_retval_t cmox_rv; /* CLv4 return value */
  int32_t retval = SIGNATURE_INVALID; /* by default, return error */

  /* synchronize CLv3 membuf to CLv4 membuf */
  cmox_helper_membuf_toV4(P_pMemBuf, (cmox_membuf_handle_st *) & (P_pVerifyCtx->pmEC->cmox_ctx.membuf_str));

  /* perform ECDSA verification with CLv4 */
  cmox_rv = cmox_ecdsa_verify((cmox_ecc_handle_t *) & (P_pVerifyCtx->pmEC->cmox_ctx), P_pVerifyCtx->pmEC->pmInternalEC,
                              P_pVerifyCtx->pmPubKey->pPoint, 2u * (size_t)P_pVerifyCtx->pmPubKey->pCurve->mPsize,
                              P_pDigest, (size_t)P_digestSize,
                              P_pSignature->pSig, 2u * (size_t)P_pVerifyCtx->pmPubKey->pCurve->mNsize,
                              NULL);

  /* properly set the return value */
  if (cmox_rv == CMOX_ECC_AUTH_SUCCESS)
  {
    retval = SIGNATURE_VALID;
  }

  return retval;
}
