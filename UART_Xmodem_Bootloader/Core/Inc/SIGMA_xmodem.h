/**
 * @file    SIGMA_xmodem.h
 * @author  SIGMA EMBEDDED
 * @date    16/10/2024
 * @brief   This module is the implementation of the Xmodem protocol.
 * @version 1.0
 * 
 *          Copyright (c) 2024 SIGMA EMBEDDED
 */

#ifndef SIGMA_XMODEM_H_
#define SIGMA_XMODEM_H_

#include "SIGMA_uart.h"
#include "SIGMA_iflash.h"

/**
 * @brief XMODEM protocol Constants 
 */
#define SOH                 0x01  // Start of 128-byte packet
#define STX                 0x02  // Start of 1024-byte packet
#define EOT                 0x04  // End of transmission
#define ACK                 0x06  // Acknowledge
#define NACK                0x15  // Negative acknowledge
#define CAN                 0x18  // Cancel transmission
#define PACKET_SIZE_128     128
#define PACKET_SIZE_1024    1024

/* Other constantes*/
#define header_size         1
#define packet_number_size  2
#define crc_size            2
/**
 * @brief Structure representing an XMODEM packet.
 * 
 * This structure holds the relevant fields of an XMODEM packet, including the
 * start byte, sequence number, payload, and checksum.
 */
typedef struct {
    uint8_t header;
    uint8_t packet_number[packet_number_size];
    uint16_t crc;
} XmodemPacket;

/**
 * @brief Status codes used in the XMODEM protocol.
 */
typedef enum {
    XMODEM_OK,               // Packet received successfully
    XMODEM_CRC_ERROR,        // CRC check failed
    XMODEM_TIMEOUT_ERROR,    // UART timeout
    XMODEM_PACKET_NUM_ERROR, // Packet number mismatch
    XMODEM_FLASH_ERROR,      // Flash write/erase error
    XMODEM_UNKNOWN_ERROR     // Any unknown error
} XmodemStatus;

/**
 * @brief Receives a file using the XMODEM protocol and writes it to flash memory.
 * 
 * This function initiates the file transfer by repeatedly sending 'C' to request 
 * the first data packet from the host. Once the transfer starts, it continues 
 * receiving packets, verifying their integrity using CRC, and writing the payload 
 * to the flash memory location of the Application. It handles errors like timeouts and 
 * CRC mismatches by sending appropriate responses (NACK) to the host and retries the 
 * reception when necessary.
 * 
 * The file transfer ends when an End of Transmission (EOT) character is received 
 * from the host, and the function responds with an ACK.
 * 
 * @return XmodemStatus Status of the operation. Possible return values:
 *         - XMODEM_OK: File received successfully.
 *         - XMODEM_TIMEOUT: Timeout while waiting for packets.
 *         - XMODEM_ERROR: Error occurred during the reception process.
 */
XmodemStatus SIGMA_Xmodem_Receive(void);

/**
 * @brief Receives a single XMODEM packet.
 * 
 * This function receives a packet from the UART, checks the CRC for integrity, and
 * handles sequence numbers.
 * 
 * @param[out] packet Pointer to the XmodemPacket structure that will hold the received data.
 * 
 * @return XmodemStatus Status of the packet reception.
 */
XmodemStatus SIGMA_Xmodem_receive_packet(XmodemPacket *packet);

/**
 * @brief Calculates the CRC-16 checksum for a given data buffer.
 * 
 * This function implements the standard CRC-16-CCITT algorithm used by XMODEM to 
 * verify data integrity.
 * 
 * @param[in] data   Pointer to the data buffer.
 * @param[in] length Length of the data buffer.
 * 
 * @return The calculated CRC-16 value.
 */
uint16_t SIGMA_Xmodem_calculate_crc16(const uint8_t *data, uint16_t length);

/**
 * @brief Sends an ACK character over UART to the host.
 * 
 * The ACK (0x06) character is used to acknowledge successful receipt of a packet.
 */
void SIGMA_Xmodem_send_ack(void);

/**
 * @brief Sends a NAK character over UART to the host.
 * 
 * The NAK (0x15) character indicates that there was an error in receiving the packet.
 */
void SIGMA_Xmodem_send_nack(void);

#endif /* SIGMA_XMODEM_H_ */
