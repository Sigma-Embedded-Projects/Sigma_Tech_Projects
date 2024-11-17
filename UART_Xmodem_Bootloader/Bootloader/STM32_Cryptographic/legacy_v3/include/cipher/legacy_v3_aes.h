/**
  *******************************************************************************
  * @file    legacy_v3_aes.h
  * @author  MCD Application Team
  * @brief   Header file of AES helper for migration of cryptographics
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

#ifndef LEGACY_V3_AES_H
#define LEGACY_V3_AES_H

#include "cipher/cmox_cipher.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/* Exported constants --------------------------------------------------------*/
#define CRL_AES128_KEY   16 /*!< Number of bytes (uint8_t) necessary to store an AES key of 128 bits. */
#define CRL_AES192_KEY   24 /*!< Number of bytes (uint8_t) necessary to store an AES key of 192 bits. */
#define CRL_AES256_KEY   32 /*!< Number of bytes (uint8_t) necessary to store an AES key of 256 bits. */


#define CRL_AES_BLOCK    16 /*!< Number of bytes (uint8_t) necessary to store an AES block. */

#define E_SK_DEFAULT (SKflags_et) (0x00000000) /*!< User Flag: No flag specified. This is the default value that should be set to this flag  */
#define E_SK_DONT_PERFORM_KEY_SCHEDULE (SKflags_et) (0x00000001) /*!< User Flag: Used to force the init to not reperform key schedule.\n
                                                                       The classic example is where the same key is used on a new message, in this case to redo key scheduling is
                                                                       a useless waste of computation, could be particularly useful on GCM, where key schedule is very complicated. */
#define E_SK_FINAL_APPEND (SKflags_et)(0x00000020)   /*!< User Flag: Must be set in CMAC mode before the final Append call occurs. */
#define E_SK_OPERATION_COMPLETED (SKflags_et)(0x00000002)   /*!< Internal Flag (not to be set/read by user): used to check that the Finish function has been already called */
#define E_SK_NO_MORE_APPEND_ALLOWED (SKflags_et)(0x00000004) /*!< Internal Flag (not to be set/read by user): it is set when the last append has been called. Used where the append is called with an InputSize not
                                                                          multiple of the block size, which means that is the last input.*/
#define E_SK_NO_MORE_HEADER_APPEND_ALLOWED (SKflags_et)(0x00000010)   /*!< Internal Flag (not to be set/read by user): only for authenticated encryption modes. \n
                                                                            It is set when the last header append has been called. Used where the header append is called with an InputSize not
                                                                            multiple of the block size, which means that is the last input.*/
#define E_SK_APPEND_DONE (SKflags_et)(0x00000040)   /*!< Internal Flag (not to be set/read by user): only for CMAC.It is set when the first append has been called */
#define E_SK_SET_COUNTER (SKflags_et)(0x00000080)    /*!< User Flag: With ChaCha20 this is used to indicate a value for the counter, used to process non contiguous blocks (i.e. jump ahead)*/

typedef uint32_t SKflags_et;    /*!< Type definitation for Symmetric Key Flags */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LEGACY_V3_AES_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
