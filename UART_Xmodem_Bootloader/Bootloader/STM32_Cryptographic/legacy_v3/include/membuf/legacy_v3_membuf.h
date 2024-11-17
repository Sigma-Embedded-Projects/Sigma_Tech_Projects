/**
  ******************************************************************************
  * @file    legacy_v3_membuf.h
  * @author  MCD Application Team
  * @brief   Header file of memory management (RSA and ECC) helper for migration
  *          of cryptographics library V3 to V4
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

#ifndef CMOX_HELPER_MEMBUF_H
#define CMOX_HELPER_MEMBUF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/**
  * @brief MemBuf structure definition
  */
typedef struct
{
  uint8_t *pmBuf; /*!< Pointer to the pre-allocated memory buffer, this must be set by the user*/
  uint16_t mSize; /*!< Total size of the pre-allocated memory buffer */
  uint16_t mUsed; /*!< Currently used portion of the buffer, should be inititalized by user to zero */
} membuf_stt;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CMOX_HELPER_MEMBUF_H */
