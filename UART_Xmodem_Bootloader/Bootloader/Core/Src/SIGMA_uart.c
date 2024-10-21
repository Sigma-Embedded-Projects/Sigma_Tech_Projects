/**
 * @file    SIGMA_uart.c
 * @author  SIGMA EMBEDDED
 * @date    16/10/2024
 * @brief   This module is a layer between the HAL UART functions and my Xmodem protocol.
 * @version 1.0
 * 
 *          Copyright (c) 2024 SIGMA EMBEDDED
 */

#include "SIGMA_uart.h"

/**
 * @brief   Receives data from UART.
 * @param   *data: Array to save the received data.
 * @param   length:  Size of the data.
 * @return  status: Report about the success of the receiving.
 */
uart_status SIGMA_Uart_Receive(uint8_t *data, uint16_t length)
{
  uart_status status = UART_ERROR;

  if (HAL_OK == HAL_UART_Receive(&hlpuart1, data, length, UART_TIMEOUT))
  {
    status = UART_OK;
  }

  return status;
}

/**
 * @brief   Transmits a string to UART.
 * @param   *data: Array of the data.
 * @return  status: Report about the success of the transmission.
 */
uart_status SIGMA_Uart_Transmit_str(uint8_t *data)
{
  uart_status status = UART_ERROR;
  uint16_t length = 0u;

  /* Calculate the length. */
  while ('\0' != data[length])
  {
    length++;
  }

  if (HAL_OK == HAL_UART_Transmit(&hlpuart1, data, length, UART_TIMEOUT))
  {
    status = UART_OK;
  }

  return status;
}

/**
 * @brief   Transmits a single char to UART.
 * @param   data: The char.
 * @return  status: Report about the success of the transmission.
 */
uart_status SIGMA_Uart_Transmit_ch(uint8_t data)
{
  uart_status status = UART_ERROR;

  /* Make available the UART module. */
  if (HAL_UART_STATE_TIMEOUT == HAL_UART_GetState(&hlpuart1))
  {
    HAL_UART_Abort(&hlpuart1);
  }

  if (HAL_OK == HAL_UART_Transmit(&hlpuart1, &data, 1u, UART_TIMEOUT))
  {
    status = UART_OK;
  }
  return status;
}
