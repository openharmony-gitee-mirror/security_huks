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

#include "hks_openssl_aes_test_mt.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_type.h"

#define BIT_NUM_OF_UINT8 8
#define HKS_AE_TAG_LEN 16

int32_t GenerateAesKey(const int keyLen, struct HksBlob *randomKey)
{
    uint32_t keySize = keyLen / BIT_NUM_OF_UINT8;
    uint8_t *Key = (uint8_t *)malloc(keySize);
    do {
        if (RAND_bytes(Key, keySize) <= 0) {
            return AES_FAILED;
        }
        randomKey->data = Key;
        randomKey->size = keySize;
    } while (0);

    return AES_SUCCESS;
}

static const EVP_CIPHER *AesCBCCrypt(uint32_t keyLen)
{
    if (keyLen == HKS_AES_KEY_SIZE_128) {
        return EVP_aes_128_cbc();
    } else if (keyLen == HKS_AES_KEY_SIZE_192) {
        return EVP_aes_192_cbc();
    } else if (keyLen == HKS_AES_KEY_SIZE_256) {
        return EVP_aes_256_cbc();
    }
    return NULL;
}

static const EVP_CIPHER *AesECBCrypt(uint32_t keyLen)
{
    if (keyLen == HKS_AES_KEY_SIZE_128) {
        return EVP_aes_128_ecb();
    } else if (keyLen == HKS_AES_KEY_SIZE_192) {
        return EVP_aes_192_ecb();
    } else if (keyLen == HKS_AES_KEY_SIZE_256) {
        return EVP_aes_256_ecb();
    }
    return NULL;
}

static const EVP_CIPHER *AesCTRCrypt(uint32_t keyLen)
{
    if (keyLen == HKS_AES_KEY_SIZE_128) {
        return EVP_aes_128_ctr();
    } else if (keyLen == HKS_AES_KEY_SIZE_192) {
        return EVP_aes_192_ctr();
    } else if (keyLen == HKS_AES_KEY_SIZE_256) {
        return EVP_aes_256_ctr();
    }
    return NULL;
}

static const EVP_CIPHER *AesGCMCrypt(uint32_t keyLen)
{
    if (keyLen == HKS_AES_KEY_SIZE_128) {
        return EVP_aes_128_gcm();
    } else if (keyLen == HKS_AES_KEY_SIZE_192) {
        return EVP_aes_192_gcm();
    } else if (keyLen == HKS_AES_KEY_SIZE_256) {
        return EVP_aes_256_gcm();
    }
    return NULL;
}

static uint32_t AesInit(EVP_CIPHER_CTX **ctx, const EVP_CIPHER **ciper, uint32_t mode, uint32_t keyLen)
{
    if (mode == HKS_MODE_GCM) {
        *ciper = AesGCMCrypt(keyLen);
    } else if (mode == HKS_MODE_CBC) {
        *ciper = AesCBCCrypt(keyLen);
    } else if (mode == HKS_MODE_ECB) {
        *ciper = AesECBCrypt(keyLen);
    } else if (mode == HKS_MODE_CTR) {
        *ciper = AesCTRCrypt(keyLen);
    }

    *ctx = EVP_CIPHER_CTX_new();
    if (*ctx == NULL) {
        EVP_CIPHER_CTX_free(*ctx);
        return AES_FAILED;
    }
    return AES_SUCCESS;
}

uint32_t AesEncrypt(const struct HksParamSet *paramSetIn, const struct HksBlob *inData, struct HksBlob *outData,
    const struct HksBlob *randomKey)
{
    struct HksParam *mode = NULL;
    HksGetParam(paramSetIn, HKS_TAG_BLOCK_MODE, &mode);
    struct HksParam *keyLen = NULL;
    HksGetParam(paramSetIn, HKS_TAG_KEY_SIZE, &keyLen);
    struct HksParam *padding = NULL;
    HksGetParam(paramSetIn, HKS_TAG_PADDING, &padding);
    struct HksParam *iv = NULL;
    HksGetParam(paramSetIn, HKS_TAG_IV, &iv);

    const EVP_CIPHER *ciper = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    if (AesInit(&ctx, &ciper, mode->uint32Param, keyLen->uint32Param) != AES_SUCCESS) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_EncryptInit_ex(ctx, ciper, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, randomKey->data, iv->blob.data) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    int ret = 1;
    if (padding->uint32Param == HKS_PADDING_PKCS7) {
        ret = EVP_CIPHER_CTX_set_padding(ctx, 1);
    } else if (padding->uint32Param == HKS_PADDING_NONE) {
        ret = EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ret;
    }

    int outLen = 0;
    if (EVP_EncryptUpdate(ctx, outData->data, &outLen, inData->data, inData->size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    outData->size = outLen;
    if (EVP_EncryptFinal_ex(ctx, outData->data + outLen, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    outData->size += outLen;
    EVP_CIPHER_CTX_free(ctx);
    return AES_SUCCESS;
}

uint32_t AesDecrypt(const struct HksParamSet *paramSetIn, const struct HksBlob *inData, struct HksBlob *outData,
    const struct HksBlob *randomKey)
{
    struct HksParam *mode = NULL;
    HksGetParam(paramSetIn, HKS_TAG_BLOCK_MODE, &mode);
    struct HksParam *keyLen = NULL;
    HksGetParam(paramSetIn, HKS_TAG_KEY_SIZE, &keyLen);
    struct HksParam *padding = NULL;
    HksGetParam(paramSetIn, HKS_TAG_PADDING, &padding);
    struct HksParam *iv = NULL;
    HksGetParam(paramSetIn, HKS_TAG_IV, &iv);

    const EVP_CIPHER *ciper = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    if (AesInit(&ctx, &ciper, mode->uint32Param, keyLen->uint32Param) != AES_SUCCESS) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_DecryptInit_ex(ctx, ciper, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, randomKey->data, iv->blob.data) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    int ret = 1;
    if (padding->uint32Param == HKS_PADDING_PKCS7) {
        ret = EVP_CIPHER_CTX_set_padding(ctx, 1);
    } else if (padding->uint32Param == HKS_PADDING_NONE) {
        ret = EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ret;
    }

    int outLen = 0;
    if (EVP_DecryptUpdate(ctx, outData->data, &outLen, inData->data, inData->size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    outData->size = outLen;
    if (EVP_DecryptFinal_ex(ctx, outData->data + outLen, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    outData->size += outLen;
    EVP_CIPHER_CTX_free(ctx);
    return AES_SUCCESS;
}

uint32_t AesGCMEncrypt(const struct HksParamSet *paramSetIn, const struct HksBlob *inData, struct HksBlob *outData,
    const struct HksBlob *randomKey, const struct HksBlob *tagAead)
{
    struct HksParam *mode = NULL;
    HksGetParam(paramSetIn, HKS_TAG_BLOCK_MODE, &mode);
    struct HksParam *keyLen = NULL;
    HksGetParam(paramSetIn, HKS_TAG_KEY_SIZE, &keyLen);
    struct HksParam *iv = NULL;
    HksGetParam(paramSetIn, HKS_TAG_NONCE, &iv);
    struct HksParam *aad = NULL;
    HksGetParam(paramSetIn, HKS_TAG_ASSOCIATED_DATA, &aad);

    const EVP_CIPHER *ciper = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    if (AesInit(&ctx, &ciper, mode->uint32Param, keyLen->uint32Param) != AES_SUCCESS) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_EncryptInit_ex(ctx, ciper, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv->blob.size, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, randomKey->data, iv->blob.data) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    int outLen = 0;
    if (EVP_EncryptUpdate(ctx, NULL, &outLen, aad->blob.data, aad->blob.size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    if (EVP_EncryptUpdate(ctx, outData->data, &outLen, inData->data, inData->size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    outData->size = outLen;
    if (EVP_EncryptFinal_ex(ctx, outData->data, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, HKS_AE_TAG_LEN, tagAead->data) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    EVP_CIPHER_CTX_free(ctx);
    return AES_SUCCESS;
}

uint32_t AesGCMDecrypt(const struct HksParamSet *paramSetIn, const struct HksBlob *inData, struct HksBlob *outData,
    const struct HksBlob *randomKey, const struct HksBlob *tagDec)
{
    struct HksParam *mode = NULL;
    HksGetParam(paramSetIn, HKS_TAG_BLOCK_MODE, &mode);
    struct HksParam *keyLen = NULL;
    HksGetParam(paramSetIn, HKS_TAG_KEY_SIZE, &keyLen);
    struct HksParam *iv = NULL;
    HksGetParam(paramSetIn, HKS_TAG_NONCE, &iv);
    struct HksParam *aad = NULL;
    HksGetParam(paramSetIn, HKS_TAG_ASSOCIATED_DATA, &aad);

    const EVP_CIPHER *ciper = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    if (AesInit(&ctx, &ciper, mode->uint32Param, keyLen->uint32Param) != AES_SUCCESS) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_DecryptInit_ex(ctx, ciper, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv->blob.size, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, randomKey->data, iv->blob.data) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }

    int outLen = 0;
    if (EVP_DecryptUpdate(ctx, NULL, &outLen, aad->blob.data, aad->blob.size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    if (EVP_DecryptUpdate(ctx, outData->data, &outLen, inData->data, inData->size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    outData->size = outLen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagDec->size, tagDec->data) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    if (EVP_DecryptFinal_ex(ctx, outData->data, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_FAILED;
    }
    EVP_CIPHER_CTX_free(ctx);
    return AES_SUCCESS;
}
