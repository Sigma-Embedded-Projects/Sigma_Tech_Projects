/**
 * @file    SIGMA_iflash.h
 * @author  SIGMA EMBEDDED
 * @date    30/09/2024
 * @brief   STM32L5 Internal Flash Driver API
 *
 *          Copyright (c) 2024 SIGMA EMBEDDED
 */

#ifndef SIGMA_IFLASH_H_
#define SIGMA_IFLASH_H_

#include "stm32l5xx_hal.h"

/* Start and end addresses of the user application. */
#define IFLASH_DOUBLE_WORD_SIZE 4*2 // Double Word Size
#define FLASH_APP_START_ADDRESS ((uint32_t)0x08020000u)
#define FLASH_APP_END_ADDRESS   ((uint32_t)FLASH_APP_START_ADDRESS + 64*1024) // Maximum size of the App is 64k - From Page 64 to 96
#define FLASH_APP_NUM_PAGES     32
#define ADDR_FLASH_PAGE_64      ((uint32_t)0x08020000) 
#define FLASH_BASE              ((uint32_t)0x08000000)
#define FLASH_BANK1_END         ((uint32_t)0x0803FFFF)

void JumpToAPP(void);
HAL_StatusTypeDef SIGMA_Iflash_Erase (uint32_t address);
HAL_StatusTypeDef SIGMA_Iflash_Read(    uint32_t             address,
                                        uint8_t           *  pData,
                                        uint32_t             size);
HAL_StatusTypeDef SIGMA_Iflash_Write(   uint32_t             address,
                                        uint8_t           *  pData,
                                        uint32_t             size);                                  

#endif /* SIGMA_IFLASH_H_ */
