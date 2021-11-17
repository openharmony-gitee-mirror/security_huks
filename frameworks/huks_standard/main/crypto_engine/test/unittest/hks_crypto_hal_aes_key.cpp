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
class HksCryptoHalAesKey : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalAesKey_001
 * @tc.name      : HksCryptoHalAesKey_001
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate AES-128bit key.
 */
HWTEST_F(HksCryptoHalAesKey, HksCryptoHalAesKey_001, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    ret = HksCryptoHalGenerateKey(&spec, &key);
#if defined(HKS_SUPPORT_AES_C) && defined(HKS_SUPPORT_AES_GENERATE_KEY)
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);
    HksFree(key.data);
#else
    ASSERT_EQ(HKS_ERROR_NOT_SUPPORTED, ret);
#endif
}

/**
 * @tc.number    : HksCryptoHalAesKey_002
 * @tc.name      : HksCryptoHalAesKey_002
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate AES-192bit key.
 */
HWTEST_F(HksCryptoHalAesKey, HksCryptoHalAesKey_002, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    ret = HksCryptoHalGenerateKey(&spec, &key);
#if defined(HKS_SUPPORT_AES_C) && defined(HKS_SUPPORT_AES_GENERATE_KEY)
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);
    HksFree(key.data);
#else
    ASSERT_EQ(HKS_ERROR_NOT_SUPPORTED, ret);
#endif
}

/**
 * @tc.number    : HksCryptoHalAesKey_003
 * @tc.name      : HksCryptoHalAesKey_003
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate AES-256bit key.
 */
HWTEST_F(HksCryptoHalAesKey, HksCryptoHalAesKey_003, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    ret = HksCryptoHalGenerateKey(&spec, &key);
#if defined(HKS_SUPPORT_AES_C) && defined(HKS_SUPPORT_AES_GENERATE_KEY)
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);
    HksFree(key.data);
#else
    ASSERT_EQ(HKS_ERROR_NOT_SUPPORTED, ret);
#endif
}
}  // namespace