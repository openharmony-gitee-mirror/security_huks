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

#ifdef HKS_SUPPORT_DH_C
#include <gtest/gtest.h>
#include <iostream>

#include "hks_mem.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_config.h"

using namespace testing::ext;
namespace {
class HksCryptoHalDh : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalDh_001
 * @tc.name      : HksCryptoHalDh_001
 * @tc.desc      : Generate Dh-2048 key pair
 */
HWTEST_F(HksCryptoHalDh, HksCryptoHalDh_001, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = { .algType = HKS_ALG_DH, .keyLen = HKS_DH_KEY_SIZE_2048 };

    HksBlob key = { 0, NULL };

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);

    HKS_FREE_BLOB(key);
}

/**
 * @tc.number    : HksCryptoHalDh_002
 * @tc.name      : HksCryptoHalDh_002
 * @tc.desc      : Generate Dh-3072 key pair
 */
HWTEST_F(HksCryptoHalDh, HksCryptoHalDh_002, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = { .algType = HKS_ALG_DH, .keyLen = HKS_DH_KEY_SIZE_3072 };

    HksBlob key = { 0, NULL };

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);

    HKS_FREE_BLOB(key);
}

/**
 * @tc.number    : HksCryptoHalDh_003
 * @tc.name      : HksCryptoHalDh_003
 * @tc.desc      : Generate Dh-4096 key pair
 */
HWTEST_F(HksCryptoHalDh, HksCryptoHalDh_003, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = { .algType = HKS_ALG_DH, .keyLen = HKS_DH_KEY_SIZE_4096 };

    HksBlob key = { 0, NULL };

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);

    HKS_FREE_BLOB(key);
}
}  // namespace
#endif