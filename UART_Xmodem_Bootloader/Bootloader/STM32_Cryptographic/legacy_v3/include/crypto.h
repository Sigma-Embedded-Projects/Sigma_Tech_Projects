/**
  ******************************************************************************
  * @file    crypto.h
  * @author  MCD Application Team
  * @brief   Main header file of helper for migration of cryptographics
  *          library V3 to V4
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

#ifndef CMOX_HELPER_H
#define CMOX_HELPER_H

/* common headers */
#include "err_codes.h"

/* HASH */
#include "hash/legacy_v3_sha1.h"
#include "hash/legacy_v3_sha224.h"
#include "hash/legacy_v3_sha256.h"
#include "hash/legacy_v3_sha384.h"
#include "hash/legacy_v3_sha512.h"

/* MAC */
#include "mac/legacy_v3_hmac_sha1.h"
#include "mac/legacy_v3_hmac_sha224.h"
#include "mac/legacy_v3_hmac_sha256.h"
#include "mac/legacy_v3_hmac_sha384.h"
#include "mac/legacy_v3_hmac_sha512.h"
#include "mac/legacy_v3_cmac.h"

/* AES */
#include "cipher/legacy_v3_aes_cbc.h"
#include "cipher/legacy_v3_aes_ccm.h"
#include "cipher/legacy_v3_aes_cfb.h"
#include "cipher/legacy_v3_aes_ctr.h"
#include "cipher/legacy_v3_aes_ecb.h"
#include "cipher/legacy_v3_aes_gcm.h"
#include "cipher/legacy_v3_aes_keywrap.h"
#include "cipher/legacy_v3_aes_ofb.h"
#include "cipher/legacy_v3_aes_xts.h"

/* CHACHA20-POLY1305 */
#include "cipher/legacy_v3_chachapoly.h"

/* DRBG */
#include "drbg/legacy_v3_ctr_drbg.h"

/* ECC */
#include "ecc/legacy_v3_c25519.h"
#include "ecc/legacy_v3_ed25519.h"
#include "ecc/legacy_v3_ecc.h"

/* RSA */
#include "rsa/legacy_v3_rsa.h"

#endif /* CMOX_HELPER_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
