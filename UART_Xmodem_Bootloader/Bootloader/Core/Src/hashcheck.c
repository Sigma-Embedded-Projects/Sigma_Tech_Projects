/**
  ******************************************************************************
  * @file    hashcheck.c
  * @brief   Example of fw hash check.
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

/* Includes ------------------------------------------------------------------*/
#include "SIGMA_main.h"
#include "crypto.h"
#include "hashcheck.h"
#include <stdio.h>
#include <string.h>

/* Private function prototypes -----------------------------------------------*/

/**
  * @brief  SHA256 HASH digest compute example.
  * @param  InputMessage: pointer to input message to be hashed.
  * @param  InputMessageLength: input data message length in byte.
  * @param  MessageDigest: pointer to output parameter that will handle message digest
  * @param  MessageDigestLength: pointer to output digest length.
  * @retval error status: can be HASH_SUCCESS if success or one of
  *         HASH_ERR_BAD_PARAMETER, HASH_ERR_BAD_CONTEXT,
  *         HASH_ERR_BAD_OPERATION if error occured.
  */
int32_t STM32_SHA256_HASH_DigestCompute(uint8_t* InputMessage, uint32_t InputMessageLength,
                                        uint8_t *MessageDigest, int32_t* MessageDigestLength)
{
  SHA256ctx_stt P_pSHA256ctx;
  uint32_t error_status = HASH_SUCCESS; 

  /* Set the size of the desired hash digest */
  P_pSHA256ctx.mTagSize = CRL_SHA256_SIZE;

  /* Set flag field to default value */
  P_pSHA256ctx.mFlags = E_HASH_DEFAULT;

  error_status = SHA256_Init(&P_pSHA256ctx);

  /* check for initialization errors */
  if (error_status == HASH_SUCCESS)
  {
    /* Add data to be hashed */
    error_status = SHA256_Append(&P_pSHA256ctx,
                                 InputMessage,
                                 InputMessageLength);

    if (error_status == HASH_SUCCESS)
    {
      /* retrieve */
      error_status = SHA256_Finish(&P_pSHA256ctx, MessageDigest, MessageDigestLength);
    }
  }

  return error_status;
}

void Fatal_Error_Handler(void)
{
  // Do nothing for the moment
  // TODO : Will be covered in another Video Inchaelah
}

/**
  * @brief  Verify the HASH value of the fw binary (with paddig)
  *         If verification fails, stays in endless loop (or can chagne to reset)
  *         those protections not impacted by a Reset. They are set using the Option Bytes
  *         When the device is locked (RDP Level2), these protections cannot be changed anymore
  * @param  None
  */
uint8_t FW_Hash_Verify(void)
{
  uint8_t MessageDigest[HASH_SIZE];
  int32_t MessageDigestLength = HASH_SIZE;
  int32_t result = -1;
  
  /* enable CRC to allow cryptolib to work */ 
  __CRC_RELEASE_RESET();
  __CRC_CLK_ENABLE();
     
  result = STM32_SHA256_HASH_DigestCompute((uint8_t*)FLASH_APP_START_ADDRESS, 
                                       (uint32_t)(FLASH_APP_Size - HASH_SIZE), 
                                       MessageDigest, 
                                       &MessageDigestLength);
  if ( result == HASH_SUCCESS && MessageDigestLength == HASH_SIZE) 
  {
    if (memcmp((uint8_t*)(HASH_ADD), MessageDigest, (uint32_t)HASH_SIZE) == 0)
    {
      return HASH_SUCCESS;
    }
    else
    {
      goto Machakil; 
    }
  }
  else
  {
    goto Machakil;
  }
  return;
  
Machakil:
  Fatal_Error_Handler();
}
