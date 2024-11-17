/**
  ******************************************************************************
  * @file    err_codes.h
  * @author  MCD Application Team
  * @brief   Error codes of cryptographics library V3
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

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __CRL_ERR_CODES_H__
#define __CRL_ERR_CODES_H__

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#define AUTHENTICATION_SUCCESSFUL          (int32_t) (1003)          /*!< Authentication successful */
#define AUTHENTICATION_FAILED              (int32_t) (1004)          /*!< Authentication failed */
#define SIGNATURE_VALID                    AUTHENTICATION_SUCCESSFUL /*!< Signature is valid */
#define SIGNATURE_INVALID                  AUTHENTICATION_FAILED     /*!< Signature is NOT valid */
#define ERR_MEMORY_FAIL                    (int32_t) (1005)          /*!< There's no more available memory */

#define AES_SUCCESS                        (int32_t) (0)             /*!< AES Success */
#define AES_ERR_BAD_INPUT_SIZE             (int32_t) (3101)          /*!< AES Invalid input size */
#define AES_ERR_BAD_OPERATION              (int32_t) (3102)          /*!< AES Invalid operation */
#define AES_ERR_BAD_CONTEXT                (int32_t) (3103)          /*!< AES context has invalid/uninitialized vals */
#define AES_ERR_BAD_PARAMETER              (int32_t) (3104)          /*!< AES function called with invalid params */

#define CHACHA_SUCCESS                     (int32_t) (0)             /*!< ChaCha Success */
#define CHACHA_ERR_BAD_INPUT_SIZE          (int32_t) (3201)          /*!< ChaCha Invalid input size */
#define CHACHA_ERR_BAD_OPERATION           (int32_t) (3202)          /*!< ChaCha Invalid operation */
#define CHACHA_ERR_BAD_CONTEXT             (int32_t) (3203)          /*!< ChaCha ctx has invalid/uninitialized vals */
#define CHACHA_ERR_BAD_PARAMETER           (int32_t) (3204)          /*!< ChaCha function called with invalid params */

#define POLY1305_SUCCESS                   (int32_t) (0)             /*!< POLY1305 Success */
#define POLY1305_ERR_BAD_OPERATION         (int32_t) (3102)          /*!< POLY1305 Invalid operation */
#define POLY1305_ERR_BAD_CONTEXT           (int32_t) (3103)          /*!< POLY1305 ctx invalid/uninitialized values */
#define POLY1305_ERR_BAD_PARAMETER         (int32_t) (3104)          /*!< POLY1305 func called with invalid params */

#define HASH_SUCCESS                       (int32_t) (0)             /*!< Hash Success */
#define HASH_ERR_BAD_OPERATION             (int32_t) (4001)          /*!< Hash Invalid operation */
#define HASH_ERR_BAD_CONTEXT               (int32_t) (4002)          /*!< Hash ctx has invalid/uninitialized vals */
#define HASH_ERR_BAD_PARAMETER             (int32_t) (4003)          /*!< Hash function called with invalid params */
#define HASH_ERR_UNSUPPORTED               (int32_t) (4004)          /*!< Hash algorithm is not supported */
#define HASH_ERR_INTERNAL                  (int32_t) (4011)          /*!< Hash Generic internal error */

#define RSA_SUCCESS                        (int32_t) (0)             /*!< RSA Success */
#define RSA_ERR_BAD_OPERATION              (int32_t) (5102)          /*!< RSA Invalid operation */
#define RSA_ERR_BAD_KEY                    (int32_t) (5103)          /*!< RSA Invalid Key */
#define RSA_ERR_BAD_PARAMETER              (int32_t) (5104)          /*!< RSA function called with invalid params */
#define RSA_ERR_UNSUPPORTED_HASH           (int32_t) (5105)          /*!< RSA hash function is not supported */
#define RSA_ERR_MESSAGE_TOO_LONG           (int32_t) (5106)          /*!< RSA Message too long */
#define RSA_ERR_MODULUS_TOO_SHORT          (int32_t) (5107)          /*!< RSA modulus too short */
#define RSA_ERR_GENERIC                    (int32_t) (5108)          /*!< RSA Generic Error */

#define ECC_SUCCESS                        (int32_t) (0)             /*!< ECC Success */
#define ECC_ERR_BAD_OPERATION              (int32_t) (5202)          /*!< ECC Invalid operation */
#define ECC_ERR_BAD_CONTEXT                (int32_t) (5203)          /*!< ECC context has invalid/uninitialized vals */
#define ECC_ERR_BAD_PARAMETER              (int32_t) (5204)          /*!< ECC function called with invalid params */
#define ECC_ERR_BAD_PUBLIC_KEY             (int32_t) (5205)          /*!< ECC Invalid Public Key */
#define ECC_ERR_BAD_PRIVATE_KEY            (int32_t) (5206)          /*!< ECC Invalid Private Key */
#define ECC_ERR_MISSING_EC_PARAMETER       (int32_t) (5207)          /*!< ECC params struct misses some parameter */
#define ECC_WARN_POINT_AT_INFINITY         (int32_t) (5208)          /*!< ECC Returned Point is point at infinity */

#define RNG_SUCCESS                        (int32_t) (0)             /*!< RNG Success */
#define RNG_ERR_UNINIT_STATE               (int32_t) (6001)          /*!< RNG has not been correctly initialized */
#define RNG_ERR_BAD_OPERATION              (int32_t) (6002)          /*!< RNG Invalid operation */
#define RNG_ERR_RESEED_NEEDED              (int32_t) (6003)          /*!< RNG Reseed is needed */
#define RNG_ERR_BAD_PARAMETER              (int32_t) (6004)          /*!< RNG function called with invalid params */
#define RNG_ERR_BAD_ENTROPY_SIZE           (int32_t) (6006)          /*!< RNG wrong size of the entropy string */
#define RNG_ERR_BAD_PERS_STRING_SIZE       (int32_t) (6007)          /*!< RNG wrong size of the personaliz. string */
#define RNG_ERR_BAD_ADD_INPUT_SIZE         (int32_t) (6008)          /*!< RNG wrong size of the add. input string */
#define RNG_ERR_BAD_REQUEST                (int32_t) (6009)          /*!< RNG wrong size of the random request */
#define RNG_ERR_BAD_NONCE_SIZE             (int32_t) (6010)          /*!< RNG wrong size of the nocne */
#define RNG_ERR_INTERNAL                   (int32_t) (6011)          /*!< RNG Generic internal RNG error */

#define ED25519_SUCCESS                    (int32_t) (0)             /*!< Ed25519 Success */
#define ED25519_ERR_BAD_POINT              (int32_t) (5505)          /*!< Ed25519 Invalid Packet Point */
#define ED25519_ERR_BAD_PARAMETER          (int32_t) (5504)          /*!< Ed25519 func called with invalid params */

#define C25519_SUCCESS                     (int32_t) (0)             /*!< Curve25519 Success */
#define C25519_ERR_BAD_POINT               (int32_t) (5605)          /*!< Curve25519 Invalid Packet Point */
#define C25519_ERR_BAD_PARAMETER           (int32_t) (5604)          /*!< Curve25519 func called with invalid params */

#define MATH_SUCCESS                       (int32_t) (0)             /*!< Math Success */
#define MATH_ERR_BIGNUM_OVERFLOW           (int32_t) (5301)          /*!< Math Overflow */
#define MATH_ERR_EVEN_MODULUS              (int32_t) (5302)          /*!< Math function used with even modulus */
#define MATH_ERR_BAD_PARAMETER             (int32_t) (5304)          /*!< Math function called with invalid params */
#define MATH_ERR_INTERNAL                  (int32_t) (5311)          /*!< Math Generic internal error */

#define CHACHA20POLY1305_SUCCESS           (int32_t) (0)             /*!< ChaCha20-Poly1305 Success */
#define CHACHA20POLY1305_ERR_BAD_OPERATION (int32_t) (3102)          /*!< ChaCha20-Poly1305 Invalid operation */
#define CHACHA20POLY1305_ERR_BAD_CONTEXT   (int32_t) (3103)          /*!< ChaCha20-Poly1305 ctx invalid/uninit. vals */
#define CHACHA20POLY1305_ERR_BAD_PARAMETER (int32_t) (3104)          /*!< ChaCha20-Poly1305 func invalid params */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CRL_ERR_CODES_H__ */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
