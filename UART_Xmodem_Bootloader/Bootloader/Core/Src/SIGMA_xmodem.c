/**
 * @file    xmodem.c
 * @author  SIGMA EMBEDDED
 * @date    16/10/2024
 * @brief   This module is the implementation of the Xmodem protocol.
 * @version 1.0
 * 
 *          Copyright (c) 2024 SIGMA EMBEDDED
 */

#include "SIGMA_xmodem.h"

// Rx Buffer
uint8_t packet_data[PACKET_SIZE_1024];

// XMODEM receive file function
XmodemStatus SIGMA_Xmodem_Receive(void) {

  XmodemPacket packet;
  uint8_t expected_packet_number = 1;
  uint32_t bytes_received = 0;
  HAL_StatusTypeDef flash_status;
  XmodemStatus receive_status;
  uint8_t is_packet_received = 0x00;

  // Send 'C' to initiate the transfer
  while (!is_packet_received) {
    SIGMA_Uart_Transmit_ch('C');  // Send 'C' to the host to start transmission
    receive_status = SIGMA_Xmodem_receive_packet(&packet);

    if (receive_status == XMODEM_OK && (packet.header == SOH || packet.header == STX)) {
        is_packet_received = 0x01;
    } else {
        // Small delay between sending 'C'
        HAL_Delay(100);
    }
  }

  // Erase flash memory at the start
  flash_status = SIGMA_Iflash_Erase(FLASH_APP_START_ADDRESS);

  if (flash_status != HAL_OK) {
    return XMODEM_FLASH_ERROR;  // Flash erase failed
  }

  while (1) {
    if (receive_status == XMODEM_OK) {

      if (packet.packet_number[0] == expected_packet_number) {
        uint32_t packet_size = (packet.header == SOH) ? PACKET_SIZE_128 : PACKET_SIZE_1024;
        // Ensure data fits within flash size
        uint32_t app_size = FLASH_APP_END_ADDRESS - FLASH_APP_START_ADDRESS;
        if (bytes_received + packet_size > app_size) {
          return XMODEM_FLASH_ERROR;  // Exceeds flash size
        }

        // Write data to flash memory
        flash_status = SIGMA_Iflash_Write(FLASH_APP_START_ADDRESS + bytes_received, packet_data, packet_size);

        if (flash_status != HAL_OK) {
          return XMODEM_FLASH_ERROR;  // Flash write failed
        }

        bytes_received += packet_size;
        expected_packet_number++;
        SIGMA_Xmodem_send_ack();  // Acknowledge successful packet reception
      } else {
        SIGMA_Xmodem_send_nack();  // Packet number mismatch
      }

    }else {
      // Handle error status
      switch (receive_status) {
        case XMODEM_CRC_ERROR:
          SIGMA_Xmodem_send_nack();  // CRC error, request retransmission
          break;
        case XMODEM_TIMEOUT_ERROR:
          SIGMA_Xmodem_send_nack();  // Timeout error
          break;
        case XMODEM_PACKET_NUM_ERROR:
          SIGMA_Xmodem_send_nack();  // Packet number mismatch
          break;
        default:
          return XMODEM_UNKNOWN_ERROR;  // Unknown error occurred
      }
    }

    // Get next packet
    receive_status = SIGMA_Xmodem_receive_packet(&packet);
  }
  return XMODEM_OK;  // File received successfully
}

// Function to receive a packet over UART
XmodemStatus SIGMA_Xmodem_receive_packet(XmodemPacket *packet) {

  // Receive header : SOH, STX, EOT
  if (SIGMA_Uart_Receive(&packet->header, header_size) != UART_OK) {
    return XMODEM_TIMEOUT_ERROR;  // Timeout or UART error
  }

  // Check if it's an end of Transmission
  if(packet->header == EOT){
	  SIGMA_Uart_Transmit_str((uint8_t*)"Jump to Application\n\r");
	  SIGMA_Xmodem_send_ack();
	  JumpToAPP();
  }

  if (SIGMA_Uart_Receive(packet->packet_number, packet_number_size) != UART_OK) {
    return XMODEM_TIMEOUT_ERROR;  // Timeout or UART error
  }

  uint16_t packet_size = (packet->header == SOH) ? PACKET_SIZE_128 : PACKET_SIZE_1024;

  // Receive packet data
  if (SIGMA_Uart_Receive(packet_data, packet_size) != UART_OK) {
    return XMODEM_TIMEOUT_ERROR;  // Timeout or UART error
  }

  // Receive CRC
  uint8_t crc_buf[crc_size];
  if (SIGMA_Uart_Receive(crc_buf, crc_size) != UART_OK) {
    return XMODEM_TIMEOUT_ERROR;  // Timeout or UART error
  }

  packet->crc = (crc_buf[0] << 8) | crc_buf[1];

  // Verify CRC
  uint16_t calculated_crc = SIGMA_Xmodem_calculate_crc16(packet_data, packet_size);

  if (calculated_crc != packet->crc) {
    return XMODEM_CRC_ERROR;  // CRC mismatch
  }

  return XMODEM_OK;  // Packet received successfully
}

// Example CRC-16 calculation function
uint16_t SIGMA_Xmodem_calculate_crc16(const uint8_t *data, uint16_t length) {
  uint16_t crc = 0x0000;
  for (uint16_t i = 0; i < length; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (uint8_t j = 0; j < 8; j++) {
      if (crc & 0x8000) {
        crc = (crc << 1) ^ 0x1021;
      } else {
        crc <<= 1;
      }
    }
  }

  return crc;
}

// Function to send ACK
void SIGMA_Xmodem_send_ack(void) {
  SIGMA_Uart_Transmit_ch(ACK);
}

// Function to send nack
void SIGMA_Xmodem_send_nack(void) {
  SIGMA_Uart_Transmit_ch(NACK); 
}
