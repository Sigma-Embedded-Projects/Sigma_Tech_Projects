/**
 * @file    SIGMA_iflash.c
 * @author  SIGMA EMBEDDED
 * @date    30/09/2024
 * @brief   STM32L5 Internal Flash Driver
 *
 *          Copyright (c) 2024 SIGMA EMBEDDED
 */

#include "SIGMA_iflash.h"

/* Function pointer for jumping to user application. */
typedef  void (*pFunction)(void);
pFunction JumpToApplication;

uint32_t FirstPage = 0, LastPage = 0, NbOfPages = 0, BankNumber = 0;

/* Helper Functions */

/**
  * @brief  Gets the page of a given address
  * @param  Addr: Address of the FLASH Memory
  * @retval The page of a given address
  */
static uint32_t SIGMA_GetPage(uint32_t Addr)
{
  uint32_t page = 0;

  if (Addr < (FLASH_BASE + FLASH_BANK_SIZE))
  {
    /* Bank 1 */
    page = (Addr - FLASH_BASE) / FLASH_PAGE_SIZE;
  }
  else
  {
    /* Bank 2 */
    page = (Addr - (FLASH_BASE + FLASH_BANK_SIZE)) / FLASH_PAGE_SIZE;
  }

  return page;
}

/**
  * @brief  Gets the bank of a given address
  * @param  Addr: Address of the FLASH Memory
  * @retval The bank of a given address
  */
static uint32_t SIGMA_GetBank(uint32_t Addr)
{
  return FLASH_BANK_1;
}

/**--------------------------------------------------------------------------------------------------------------------
 * @fn      IFLASH_EraseSector
 * @brief   Erases a block starting at address (which must be block aligned)
 *
 * Unlocking Internal Flash before doing any action
 *
 * @return  Standard 1/FALSE
 */

HAL_StatusTypeDef SIGMA_Iflash_Erase (uint32_t address) {
      
	HAL_StatusTypeDef      status          = HAL_OK;
	uint32_t               PageError       = 0u;
	FLASH_EraseInitTypeDef EraseInitStruct = {};

	//
	// Unlock the flash to enable the flash control register access.
	//
	HAL_FLASH_Unlock();

  /* Erase the user Flash area
  (area defined by FLASH_USER_START_ADDR and FLASH_USER_END_ADDR) ***********/

  /* Get the 1st page to erase */
  FirstPage = SIGMA_GetPage(address);

  /* Get the last page to erase */
  LastPage = SIGMA_GetPage(FLASH_BANK1_END);

  /* Get the number of pages to erase from 1st page */
  NbOfPages = LastPage - FirstPage + 1;

  /* Get the bank */
  BankNumber = SIGMA_GetBank(address);

	//
	// Setup to erase the user flash area a sector at a time.
	//
	EraseInitStruct.Banks         = BankNumber;
	EraseInitStruct.TypeErase     = FLASH_TYPEERASE_PAGES;
	EraseInitStruct.NbPages       = NbOfPages;
	EraseInitStruct.Page          = FirstPage;

	//
	// Erase sectors in increasing order until complete or error encountered.
	//

	if(HAL_FLASHEx_Erase(&EraseInitStruct, &PageError) != HAL_OK) {
		status = HAL_ERROR;
  }

	//
	// Lock the flash to disable the flash control register access. (recommended
	// to protect the flash memory against possible unwanted operation)
	//
	HAL_FLASH_Lock();

	ERROR:
	    //
	    // If any unahndled error still remains, return 1, otherwise 0.
	    //
	    return status;
    
}
/**--------------------------------------------------------------------------------------------------------------------
 * @fn      SIGMA_Iflash_Write
 * @brief   Write a buffer to the flash

 * @param   address  Starting address; must be erase-block-aligned
 * @param   pData    Pointer to the data buffer
 * @param   size     Size of the data buffer
 * @return  Standard 1/0
 */
uint64_t bytesTo64Bit(uint8_t * bytes) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((uint64_t)bytes[i] << (8 * i));
    }
    return result;
}

/**--------------------------------------------------------------------------------------------------------------------
 * @fn      SIGMA_Iflash_Write
 * @brief   Write a buffer to the flash

 * @param   address  Starting address; must be erase-block-aligned
 * @param   pData    Pointer to the data buffer
 * @param   size     Size of the data buffer
 * @return  Standard 1/0
 */
HAL_StatusTypeDef SIGMA_Iflash_Write(   uint32_t             address,
                                        uint8_t     *        pData,
                                        uint32_t             size) {

	uint32_t  nBytesWritten       = 0;
	HAL_StatusTypeDef   status    = HAL_OK;
  uint64_t Data_64 = 0;

	//
	// If the size of the data buffer is zero, skip.
	//
	if (!size) {
	  status = HAL_ERROR;
    goto ERROR;
	}
	//
	// Unlock the flash to enable the flash control register access.
	//
	HAL_FLASH_Unlock();
	//
	// Program the user flash area a user double word at a time.
	//

	do {
    //Data_64 = bytesTo64Bit(pData);

	  if(HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, address, *((uint64_t *) pData)) == HAL_OK){
      address        += IFLASH_DOUBLE_WORD_SIZE ;
	    nBytesWritten  += IFLASH_DOUBLE_WORD_SIZE ;
      pData          += IFLASH_DOUBLE_WORD_SIZE ; // Point to next Double word

    }else{
      status = HAL_ERROR;
    }

	} while ((nBytesWritten < size) && (status != HAL_ERROR));

	//
	// Lock the flash to disable the flash control register access. (recommended
	// to protect the flash memory against possible unwanted operation)
	//
	HAL_FLASH_Lock();

	ERROR:
	  //
	  // If any unahndled error still remains, return 1, otherwise 0.
	  //
	  return status;
}

/**--------------------------------------------------------------------------------------------------------------------
 * @fn      SIGMA_Iflash_Read
 * @brief   Read a buffer to the flash
 *
 * Internal Flash is memory mapped
 *
 * @param   address  Starting address; must be erase-block-aligned
 * @param   pData    Pointer to the data buffer
 * @param   size     Size of the data buffer
 * @return  Standard 1/0
 */
HAL_StatusTypeDef SIGMA_Iflash_Read(        uint32_t             address,
                                            uint8_t           *  pData,
                                            uint32_t             size) {

  if (!size)
    return HAL_OK;

  while (size){
    /* Byte by Byte Reading */
    *pData = *((uint8_t *)address);
    address ++;
    pData++;
        
    size--;
  }
  
  return HAL_OK;
}

/**
 * @brief   Jump to Main Application.
 * @param   void
 * @return  void
 */

void JumpToAPP(void){

	/* Disable Systick interrupt */
	__disable_irq();
	SysTick->CTRL &= ~SysTick_CTRL_TICKINT_Msk;

	/* Initialize user application's Stack Pointer & Jump to user application */
	JumpToApplication = (pFunction) (*(__IO uint32_t*) (FLASH_APP_START_ADDRESS + 4));

	__set_MSP(*(__IO uint32_t*) FLASH_APP_START_ADDRESS);
  __DSB();
  __DMB();
  __ISB();

	JumpToApplication();
}


