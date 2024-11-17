/**
  ******************************************************************************
  * @file    hashcheck.h
  * @brief   Header file of fw hash check module.
  *          This file provides set of firmware functions to manage Com
  *          functionalities.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2020 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under Ultimate Liberty license
  * SLA0044, the "License"; You may not use this file except in compliance with
  * the License. You may obtain a copy of the License at:
  *                             www.st.com/SLA0044
  *
  ******************************************************************************
  */
#ifndef __HASHCHECK_H
#define __HASHCHECK_H

#include "SIGMA_main.h"
#include "SIGMA_iflash.h"

/* Hash data is placed at the last page of the flash*/
#define HASH_SIZE (32)
#define HASH_ADD  (FLASH_APP_END_ADDRESS - HASH_SIZE)

int32_t STM32_SHA256_HASH_DigestCompute(uint8_t* InputMessage, uint32_t InputMessageLength,
                                        uint8_t *MessageDigest, int32_t* MessageDigestLength);
uint8_t FW_Hash_Verify(void);
void Fatal_Error_Handler(void);

#endif /* __HASHCHECK_H */
