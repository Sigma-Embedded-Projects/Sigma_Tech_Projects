/**
  ******************************************************************************
  * @file    legacy_v3_membuf.c
  * @author  MCD Application Team
  * @brief   This file provides RSA and ECC functions of helper for
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

#include "membuf/legacy_v3_membuf_internal.h"

/* Allocate a buffer */
uint32_t clv3_allocate(membuf_stt *P_pMemBuf, uint8_t **P_pBuf, uint16_t P_BufLen)
{
  uint32_t retval = 1u;

  /* check if we have memory enough */
  if ((P_pMemBuf->mUsed + P_BufLen) <= P_pMemBuf->mSize)
  {
    *P_pBuf = &(P_pMemBuf->pmBuf[P_pMemBuf->mUsed]); /* set the resulting pointer */
    P_pMemBuf->mUsed += P_BufLen; /* increase the size of used memory */

    retval = 0u;
  }

  return retval;
}

/* Free a buffer */
uint32_t clv3_free(membuf_stt *P_pMemBuf, uint8_t **P_pBuf, uint16_t P_BufLen)
{
  uint32_t retval = 1u;

  /* check if we have enough used memory */
  if (P_pMemBuf->mUsed >= P_BufLen)
  {
    *P_pBuf = NULL; /* reset the pointer */
    P_pMemBuf->mUsed -= P_BufLen; /* decrease the size of used memory */

    retval = 0u;
  }

  return retval;
}

/* Update CLv3 memory buffer structure from CLv4 memory buffer structure */
void cmox_helper_membuf_fromV4(const cmox_membuf_handle_st *P_pMemBufV4, membuf_stt *P_pMemBufV3)
{
  P_pMemBufV3->pmBuf = P_pMemBufV4->MemBuf; /* set the buffer pointer */
  P_pMemBufV3->mSize = (uint16_t)P_pMemBufV4->MemBufSize; /* set the buffer size */
  P_pMemBufV3->mUsed = (uint16_t)P_pMemBufV4->MemBufUsed; /* set the used size */
}

/* Update CLv4 memory buffer structure from CLv3 memory buffer structure */
void cmox_helper_membuf_toV4(const membuf_stt *P_pMemBufV3, cmox_membuf_handle_st *P_pMemBufV4)
{
  /* check for null parameter */
  if ((P_pMemBufV3 != NULL) && (P_pMemBufV4 != NULL))
  {
    P_pMemBufV4->MemBuf = P_pMemBufV3->pmBuf; /* set the buffer pointer */
    P_pMemBufV4->MemBufSize = P_pMemBufV3->mSize; /* set the buffer size */
    P_pMemBufV4->MemBufUsed = P_pMemBufV3->mUsed; /* set the used size */
  }
}

