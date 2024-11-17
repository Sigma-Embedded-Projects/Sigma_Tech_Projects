/**
  *******************************************************************************
  * @file    legacy_v3_hash.h
  * @author  MCD Application Team
  * @brief   Header file of HASH helper for migration of cryptographics
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

#ifndef LEGACY_V3_HASH_H
#define LEGACY_V3_HASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#define E_HASH_DEFAULT (HashFlags_et)(0x00000000U) /*!< User Flag: No flag specified.
                                                        This is the default value that should be set to this flag. */
#define E_HASH_DONT_PERFORM_KEY_SCHEDULE (HashFlags_et)(0x00000001U) /*!< User Flag: Used to force the init to not
                                                                          reperform key processing in HMAC mode. */

/**
  * @brief  Type definition for Hash/Hmac Flags
  */
typedef uint32_t HashFlags_et;


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* LEGACY_V3_HASH_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
