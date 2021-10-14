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
class HksCryptoHalApiOpenssl : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalApiOpenssl_001
 * @tc.name      : HksCryptoHalApiOpenssl_001
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate key -- key is NULL.
 */
HWTEST_F(HksCryptoHalApiOpenssl, HksCryptoHalApiOpenssl_001, Function | SmallTest | Level1)
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
 * @tc.number    : HksCryptoHalApiOpenssl_002
 * @tc.name      : HksCryptoHalApiOpenssl_002
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate key -- algType is invalid.
 */
HWTEST_F(HksCryptoHalApiOpenssl, HksCryptoHalApiOpenssl_002, Function | SmallTest | Level1)
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
 * @tc.number    : HksCryptoHalApiOpenssl_003
 * @tc.name      : HksCryptoHalApiOpenssl_003
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate key -- keyLen is invalid.
 */
HWTEST_F(HksCryptoHalApiOpenssl, HksCryptoHalApiOpenssl_003, Function | SmallTest | Level1)
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

    spec.algType = HKS_ALG_RSA;
    ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.number    : HksCryptoHalApiOpenssl_004
 * @tc.name      : HksCryptoHalApiOpenssl_004
 * @tc.desc      : Using HksCryptoHalEncrypt -- parameter is invalid.
 */
HWTEST_F(HksCryptoHalApiOpenssl, HksCryptoHalApiOpenssl_004, Function | SmallTest | Level1)
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
 * @tc.number    : HksCryptoHalApiOpenssl_005
 * @tc.name      : HksCryptoHalApiOpenssl_005
 * @tc.desc      : Using HksCryptoHalDecrypt -- parameter is invalid.
 */
HWTEST_F(HksCryptoHalApiOpenssl, HksCryptoHalApiOpenssl_005, Function | SmallTest | Level1)
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
 * @tc.number    : HksCryptoHalApiOpenssl_006
 * @tc.name      : HksCryptoHalApiOpenssl_006
 * @tc.desc      : Using HksCryptoHalEncrypt -- AES encrypt parameter is invalid.
 */
HWTEST_F(HksCryptoHalApiOpenssl, HksCryptoHalApiOpenssl_006, Function | SmallTest | Level1)
{
    int32_t ret;

    uint8_t buff[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)] = {0};
    HksBlob key = {.size = 1, .data = buff};
    HksUsageSpec spec = {.algType = HKS_ALG_AES, .mode = 0xffff};
    HksBlob message = {.size = 1, .data = buff};
    HksBlob cipherText = {.size = 1, .data = buff};
    HksBlob tagAead = {.size = 1, .data = buff};

    ret = HksCryptoHalEncrypt(&key, &spec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    spec.mode = HKS_MODE_CBC;
    ret = HksCryptoHalEncrypt(&key, &spec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    spec.mode = HKS_MODE_CTR;
    ret = HksCryptoHalEncrypt(&key, &spec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    spec.mode = HKS_MODE_ECB;
    ret = HksCryptoHalEncrypt(&key, &spec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    spec.mode = HKS_MODE_GCM;
    ret = HksCryptoHalEncrypt(&key, &spec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_ERROR_CRYPTO_ENGINE_ERROR, ret);
}

/**
 * @tc.number    : HksCryptoHalApiOpenssl_007
 * @tc.name      : HksCryptoHalApiOpenssl_007
 * @tc.desc      : Using HksCryptoHalDecrypt -- AES decrypt parameter is invalid.
 */
HWTEST_F(HksCryptoHalApiOpenssl, HksCryptoHalApiOpenssl_007, Function | SmallTest | Level1)
{
    int32_t ret;

    uint8_t buff[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)] = {0};
    HksBlob key = {.size = 1, .data = buff};
    HksUsageSpec spec = {.algType = HKS_ALG_AES, .mode = 0xffff};
    HksBlob message = {.size = 1, .data = buff};
    HksBlob cipherText = {.size = 1, .data = buff};

    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    key.size = sizeof(buff);
    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    spec.mode = HKS_MODE_GCM;
    key.size = 1;
    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_CRYPTO_ENGINE_ERROR, ret);
}

/**
 * @tc.number    : HksCryptoHalApiOpenssl_008
 * @tc.name      : HksCryptoHalApiOpenssl_008
 * @tc.desc      : Using HksCryptoHalDecrypt -- decrypt padding is invalid.
 */
HWTEST_F(HksCryptoHalApiOpenssl, HksCryptoHalApiOpenssl_008, Function | SmallTest | Level1)
{
    int32_t ret;

    uint8_t buff[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)] = {0};
    HksBlob key = {.size = sizeof(buff), .data = buff};
    HksUsageSpec spec = {.algType = HKS_ALG_AES, .mode = HKS_MODE_CBC, .padding = HKS_PADDING_PSS};
    HksBlob message = {.size = 1, .data = buff};
    HksBlob cipherText = {.size = 1, .data = buff};

    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_CRYPTO_ENGINE_ERROR, ret);

    spec.mode = HKS_MODE_ECB;
    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_ERROR_CRYPTO_ENGINE_ERROR, ret);

    spec.algType = HKS_ALG_RSA;
    ret = HksCryptoHalDecrypt(&key, &spec, &message, &cipherText);
    EXPECT_EQ(HKS_FAILURE, ret);
}
}  // namespace