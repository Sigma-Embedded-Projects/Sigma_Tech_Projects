/**
  ******************************************************************************
  * @file    legacy_v3_membuf.h
  * @author  MCD Application Team
  * @brief   Internal Header file of memory management (RSA and ECC) helper
  *          for migration of cryptographics library V3 to V4
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

#ifndef CMOX_HELPER_MEMBUF_INT_H
#define CMOX_HELPER_MEMBUF_INT_H

#include <stdint.h>
#include "membuf/legacy_v3_membuf.h"
#include "cmox_common.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/**
  * @brief Allocate a buffer
  * @param[in,out]  *P_pMemBuf  Pointer to the memory buffer structure
  * @param[out]     *P_pBuf     Pointer to a buffer that will be allocated
  * @param[in]      P_BufLen    Number of bytes to allocate
  * @return 0 if Success, 1 if not enough available memory
  */
uint32_t clv3_allocate(membuf_stt *P_pMemBuf, uint8_t **P_pBuf, uint16_t P_BufLen);

/**
  * @brief Free a buffer
  * @param[in,out]  *P_pMemBuf  Pointer to the memory buffer structure
  * @param[out]     *P_pBuf     Pointer to a buffer that will be freed
  * @param[in]      P_BufLen    Number of bytes to free
  * @return 0 if Success, -1 if it's freeing more than allocated
  */
uint32_t clv3_free(membuf_stt *P_pMemBuf, uint8_t **P_pBuf, uint16_t P_BufLen);

/**
  * @brief Update CLv3 memory buffer structure from CLv4 memory buffer structure
  * @param[in]  *P_pMemBufV4  Pointer to the CLv4 memory buffer structure
  * @param[out] *P_pMemBufV3  Pointer to the CLv3 memory buffer structure
  */
void cmox_helper_membuf_fromV4(const cmox_membuf_handle_st *P_pMemBufV4, membuf_stt *P_pMemBufV3);

/**
  * @brief Update CLv4 memory buffer structure from CLv3 memory buffer structure
  * @param[in]  *P_pMemBufV3  Pointer to the CLv3 memory buffer structure
  * @param[out] *P_pMemBufV4  Pointer to the CLv4 memory buffer structure
  */
void cmox_helper_membuf_toV4(const membuf_stt *P_pMemBufV3, cmox_membuf_handle_st *P_pMemBufV4);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CMOX_HELPER_MEMBUF_INT_H */
