
/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HKS_OPENSSL_RSA_TEST_MT_H
#define HKS_OPENSSL_RSA_TEST_MT_H

#include <stdbool.h>

#include "hks_type.h"
#include "openssl/aes.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/ossl_typ.h"
#include "openssl/rand.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AAD_SIZE 16
#define AES_FAILED ((uint32_t)1)
#define AES_SUCCESS ((uint32_t)0)
#define COMPLEMENT_LEN 16
#define IV_SIZE 16
#define OUT_PARAMSET_SIZE 2048

int32_t GenerateAesKey(const int key_len, struct HksBlob *randomKey);

uint32_t AesEncrypt(const struct HksParamSet *paramSetIn, const struct HksBlob *inData, struct HksBlob *outData,
    const struct HksBlob *randomKey);

uint32_t AesDecrypt(const struct HksParamSet *paramSetIn, const struct HksBlob *inData, struct HksBlob *outData,
    const struct HksBlob *randomKey);

uint32_t AesGCMEncrypt(const struct HksParamSet *paramSetIn, const struct HksBlob *inData, struct HksBlob *outData,
    const struct HksBlob *randomKey, const struct HksBlob *tagAead);

uint32_t AesGCMDecrypt(const struct HksParamSet *paramSetIn, const struct HksBlob *inData, struct HksBlob *outData,
    const struct HksBlob *randomKey, const struct HksBlob *tagDec);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  // CIPHER_H