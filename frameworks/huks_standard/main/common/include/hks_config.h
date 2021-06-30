/*
 * Copyright (c) 2021-2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HKS_CONFIG_H
#define HKS_CONFIG_H

#ifdef HKS_SUPPORT_PRODUCT_GT_WATCH
#define HKS_SUPPORT_LITE_HEAP
#endif

#ifdef HKS_SUPPORT_PRODUCT_WINDOWS_PC
#define HKS_SUPPORT_UPGRADE_STORAGE_DATA
#endif

/* AES */
#define HKS_SUPPORT_AES_C
#define HKS_SUPPORT_AES_GENERATE_KEY
#define HKS_SUPPORT_AES_CBC_NOPADDING
#define HKS_SUPPORT_AES_CBC_PKCS7
#define HKS_SUPPORT_AES_GCM
#ifdef HKS_SUPPORT_PRODUCT_GT_WATCH
#define HKS_SUPPORT_AES_CCM
#endif

#define HKS_SUPPORT_POSIX

/* BN */
#define HKS_SUPPORT_BN_C

/* ECC */
#ifndef HKS_SUPPORT_PRODUCT_GT_WATCH
#define HKS_SUPPORT_ECC_C
#define HKS_SUPPORT_ECC_GENERATE_KEY
#define HKS_SUPPORT_ECC_GET_PUBLIC_KEY
#define HKS_SUPPORT_ECDH_C
#define HKS_SUPPORT_ECDSA_C
#endif

/* ED25519 */
#ifndef HKS_SUPPORT_PRODUCT_GT_WATCH
#define HKS_SUPPORT_ED25519_C
#define HKS_SUPPORT_ED25519_GENERATE_KEY
#define HKS_SUPPORT_ED25519_SIGN_VERIFY
#define HKS_SUPPORT_ED2519_GET_PUBLIC_KEY
#endif

/* HASH */
#define HKS_SUPPORT_HASH_C

/* HMAC */
#define HKS_SUPPORT_HMAC_C

/* KDF */
#define HKS_SUPPORT_KDF_C
#define HKS_SUPPORT_KDF_PBKDF2
#define HKS_SUPPORT_KDF_HKDF

/* RSA */
#ifndef HKS_SUPPORT_PRODUCT_GT_WATCH
#define HKS_SUPPORT_RSA_C
#define HKS_SUPPORT_RSA_GENERATE_KEY
#define HKS_SUPPORT_RSA_CRYPT
#define HKS_SUPPORT_RSA_SIGN_VERIFY
#define HKS_SUPPORT_RSA_GET_PUBLIC_KEY
#endif

/* X25519 */
#define HKS_SUPPORT_X25519_C
#define HKS_SUPPORT_X25519_GENERATE_KEY
#define HKS_SUPPORT_X25519_AGREE_KEY
#define HKS_SUPPORT_X25519_GET_PUBLIC_KEY

#ifdef L2_STANDARD
#define HKS_SUPPORT_AGREE_TO_SAVE
#endif

#ifdef HKS_SUPPORT_AGREE_TO_SAVE /* default: disable */
#define HKS_SUPPORT_ED25519_TO_X25519
#endif

#if defined(CHIP_VER_Hi3861)
#undef HKS_SUPPORT_RSA_C
#undef HKS_SUPPORT_ECC_C
#endif

#if defined(HKS_SUPPORT_AES_GENERATE_KEY) || defined(HKS_SUPPORT_ECC_GENERATE_KEY) || \
    defined(HKS_SUPPORT_ED25519_GENERATE_KEY) || defined(HKS_SUPPORT_RSA_GENERATE_KEY) || \
    defined(HKS_SUPPORT_X25519_GENERATE_KEY)
#define HKS_SUPPORT_API_GENERATE_KEY
#define HKS_SUPPORT_API_DELETE_KEY
#define HKS_SUPPORT_API_GET_KEY_PARAM_SET
#define HKS_SUPPORT_API_KEY_EXIST
#endif

#if defined(HKS_SUPPORT_ECC_C) || defined(HKS_SUPPORT_RSA_C) || \
    defined(HKS_SUPPORT_ED25519_C) || defined(HKS_SUPPORT_X25519_C) || \
    defined(HKS_SUPPORT_AES_C)
#define HKS_SUPPORT_API_IMPORT
#endif

#if defined(HKS_SUPPORT_ECC_C) || defined(HKS_SUPPORT_RSA_C) || \
    defined(HKS_SUPPORT_ED25519_C) || defined(HKS_SUPPORT_X25519_C)
#define HKS_SUPPORT_API_EXPORT
#endif

#define HKS_SUPPORT_API_GENERATE_RANDOM

#if defined(HKS_SUPPORT_ECDSA_C) || defined(HKS_SUPPORT_ED25519_SIGN_VERIFY) || \
    defined(HKS_SUPPORT_RSA_SIGN_VERIFY)
#define HKS_SUPPORT_API_SIGN_VERIFY
#endif

#if defined(HKS_SUPPORT_AES_C) || defined(HKS_SUPPORT_RSA_CRYPT)
#define HKS_SUPPORT_API_CIPHER
#endif

#if defined(HKS_SUPPORT_X25519_AGREE_KEY) || defined(HKS_SUPPORT_ECDH_C)
#define HKS_SUPPORT_API_AGREE_KEY
#endif

#ifdef HKS_SUPPORT_KDF_C
#define HKS_SUPPORT_API_DERIVE_KEY
#endif

#ifdef HKS_SUPPORT_HMAC_C
#define HKS_SUPPORT_API_MAC
#endif

#ifdef HKS_SUPPORT_HASH_C
#define HKS_SUPPORT_API_HASH
#endif

#ifdef HKS_SUPPORT_BN_C
#define HKS_SUPPORT_API_BN_EXP_MOD
#endif

#ifndef HKS_SUPPORT_LITE_HEAP
#define HKS_SUPPORT_API_GET_KEY_INFO_LIST
#endif

#if defined(HKS_SUPPORT_PRODUCT_ROUTER) || defined(HKS_SUPPORT_PRODUCT_CPE)
#define HKS_SUPPORT_API_ATTEST_KEY
#define HKS_SUPPORT_API_GET_CERTIFICATE_CHAIN
#define HKS_SUPPORT_API_WRAP_KEY
#define HKS_SUPPORT_API_UNWRAP_KEY
#endif

#endif /* HKS_CONFIG_H */
