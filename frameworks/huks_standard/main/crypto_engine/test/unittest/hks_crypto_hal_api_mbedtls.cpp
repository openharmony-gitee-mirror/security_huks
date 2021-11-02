/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <iostream>

#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace {
class HksCryptoHalApiMbedtls : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalApiMbedtls_001
 * @tc.name      : HksCryptoHalApiMbedtls_001
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate key -- key is NULL.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_001, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    };

    ret = HksCryptoHalGenerateKey(&spec, NULL);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_002
 * @tc.name      : HksCryptoHalApiMbedtls_002
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate key -- algType is invalid.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_002, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = 0xffff,
        .keyLen = 0,
        .algParam = nullptr,
    };

    HksBlob key = {};

    ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_003
 * @tc.name      : HksCryptoHalApiMbedtls_003
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate key -- algType is AES keyLen is invalid.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_003, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = 0,
        .algParam = nullptr,
    };

    HksBlob key = {};

    ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_004
 * @tc.name      : HksCryptoHalApiMbedtls_004
 * @tc.desc      : Using HksCryptoHalEncrypt -- parameter is invalid.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_004, Function | SmallTest | Level1)
{
    int32_t ret;

    HksBlob key = {.size = 0, .data = nullptr};
    HksUsageSpec spec = {.algType = 0xffff};
    HksBlob message = {.size = 0, .data = nullptr};
    HksBlob cipherText = {.size = 0, .data = nullptr};
    HksBlob tagAead = {.size = 0, .data = nullptr};
    uint8_t buff[1] = {0};

    ret = HksCryptoHalEncrypt(&key, nullptr, &message, &cipherText, &tagAead);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    key = {.size = 1, .data = buff};
    ret = HksCryptoHalEncrypt(&key, nullptr, &message, &cipherText, &tagAead);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    message = {.size = 1, .data = buff};
    ret = HksCryptoHalEncrypt(&key, nullptr, &message, &cipherText, &tagAead);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    cipherText = {.size = 1, .data = buff};
    ret = HksCryptoHalEncrypt(&key, nullptr, &message, &cipherText, &tagAead);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    ret = HksCryptoHalEncrypt(&key, &spec, &message, &cipherText, &tagAead);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_005
 * @tc.name      : HksCryptoHalApiMbedtls_005
 * @tc.desc      : Using HksCryptoHalDecrypt -- parameter is invalid.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_005, Function | SmallTest | Level1)
{
    int32_t ret;

    HksBlob key = {.size = 0, .data = nullptr};
    HksUsageSpec spec = {.algType = 0xffff};
    HksBlob message = {.size = 0, .data = nullptr};
    HksBlob cipherText = {.size = 0, .data = nullptr};
    uint8_t buff[1] = {0};

    ret = HksCryptoHalDecrypt(&key, nullptr, &message, &cipherText);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    key = {.size = 1, .data = buff};
    ret = HksCryptoHalDecrypt(&key, nullptr, &message, &cipherText);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    message = {.size = 1, .data = buff};
    ret = HksCryptoHalDecrypt(&key, nullptr, &message, &cipherText);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    cipherText = {.size = 1, .data = buff};
    ret = HksCryptoHalDecrypt(&key, nullptr, &message, &cipherText);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_006
 * @tc.name      : HksCryptoHalApiMbedtls_006
 * @tc.desc      : Using HksCryptoHalEncrypt -- AES encrypt parameter is invalid.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_006, Function | SmallTest | Level1)
{
    int32_t ret;

    uint8_t buff[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)] = {0};
    HksBlob key = {.size = 1, .data = buff};
    HksUsageSpec spec = {.algType = HKS_ALG_AES, .mode = 0xffff};
    HksBlob message = {.size = 1, .data = buff};
    HksBlob cipherText = {.size = 1, .data = buff};
    HksBlob tagAead = {.size = 1, .data = buff};

    ret = HksCryptoHalEncrypt(&key, &spec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_ERROR_INVALID_KEY_SIZE, ret);

    key.size = sizeof(buff);
    ret = HksCryptoHalEncrypt(&key, &spec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_007
 * @tc.name      : HksCryptoHalApiMbedtls_007
 * @tc.desc      : Using HksCryptoHalDecrypt -- AES decrypt parameter is invalid.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_007, Function | SmallTest | Level1)
{
    int32_t ret;

    uint8_t buff[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)] = {0};
    HksBlob key = {.size = 1, .data = buff};
    HksUsageSpec spec = {.algType = HKS_ALG_AES, .mode = 0xffff};
    HksBlob message = {.size = 1, .data = buff};
    HksBlob cipherText = {.size = 1, .data = buff};

    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_KEY_SIZE, ret);

    key.size = sizeof(buff);
    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_008
 * @tc.name      : HksCryptoHalApiMbedtls_008
 * @tc.desc      : Using HksCryptoHalDecrypt -- AES decrypt padding is invalid.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_008, Function | SmallTest | Level1)
{
    int32_t ret;

    uint8_t buff[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)] = {0};
    HksBlob key = {.size = sizeof(buff), buff};
    HksUsageSpec spec = {.algType = HKS_ALG_AES, .mode = HKS_MODE_CBC, .padding = HKS_PADDING_PSS};
    HksBlob message = {.size = 1, .data = buff};
    HksBlob cipherText = {.size = 1, .data = buff};

    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_PADDING, ret);

    spec.mode = HKS_MODE_ECB;
    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_PADDING, ret);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_009
 * @tc.name      : HksCryptoHalApiMbedtls_009
 * @tc.desc      : Using HksCryptoHalDecrypt -- AES decrypt CBC mode nopadding with large iv.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_009, Function | SmallTest | Level1)
{
    int32_t ret;

    uint8_t buff[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)] = {0};
    uint8_t iv[20] = {0};
    HksBlob key = {.size = sizeof(buff), buff};
    HksCipherParam cipherParam = {.iv = {.size = sizeof(iv), .data = iv}};
    HksUsageSpec spec = {.algType = HKS_ALG_AES, .mode = HKS_MODE_CBC, .padding = HKS_PADDING_NONE};
    HksBlob message = {.size = 1, .data = buff};
    HksBlob cipherText = {.size = 1, .data = buff};

    spec.algParam = &cipherParam;
    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_IV, ret);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_010
 * @tc.name      : HksCryptoHalApiMbedtls_010
 * @tc.desc      : Using HksCryptoHalDecrypt -- RSA decrypt key is invalid.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_010, Function | SmallTest | Level1)
{
    int32_t ret;

    uint8_t buff[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)] = {0};
    uint8_t iv[20] = {0};
    HksBlob key;
    HksCipherParam cipherParam = {.iv = {.size = sizeof(iv), .data = iv}};
    HksUsageSpec spec = {.algType = HKS_ALG_RSA, .mode = HKS_MODE_ECB, .padding = HKS_PADDING_NONE};
    HksBlob message = {.size = 1, .data = buff};
    HksBlob cipherText = {.size = 1, .data = buff};
    spec.algParam = &cipherParam;

    uint32_t keyLen = sizeof(KeyMaterialRsa) + HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096) +
                      HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096) +
                      (HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096) + HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096));
    key = {.size = keyLen, .data = (uint8_t *)HksMalloc(keyLen)};
    KeyMaterialRsa *keyMaterial = (KeyMaterialRsa *)key.data;
    keyMaterial->keyAlg = HKS_ALG_RSA;
    keyMaterial->keySize = HKS_RSA_KEY_SIZE_4096;
    keyMaterial->nSize = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    keyMaterial->eSize = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    keyMaterial->dSize = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096) + HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);

    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    key.size -= HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    keyMaterial->dSize = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    keyMaterial->keySize = 2000;
    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_KEY_SIZE, ret);

    key.size = sizeof(KeyMaterialRsa);
    keyMaterial->keySize = HKS_RSA_KEY_SIZE_4096;
    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_KEY_INFO, ret);
    HKS_FREE_BLOB(key);
}

/**
 * @tc.number    : HksCryptoHalApiMbedtls_011
 * @tc.name      : HksCryptoHalApiMbedtls_011
 * @tc.desc      : Using HksMbedtlsGetRsaPubKey -- RSA in/out key is invalid.
 */
HWTEST_F(HksCryptoHalApiMbedtls, HksCryptoHalApiMbedtls_011, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
    };
    HksBlob key = {.size = 0, .data = NULL};

    ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(ret, HKS_SUCCESS);

    KeyMaterialRsa *keyMaterial = (KeyMaterialRsa *)key.data;

    uint32_t keyOutLen = sizeof(KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize;
    HksBlob keyOut = {.size = sizeof(KeyMaterialRsa), .data = (uint8_t *)HksMalloc(keyOutLen)};

    keyMaterial->keySize = 2000;
    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE);

    keyMaterial->keySize = HKS_RSA_KEY_SIZE_2048;
    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);
}
}  // namespace