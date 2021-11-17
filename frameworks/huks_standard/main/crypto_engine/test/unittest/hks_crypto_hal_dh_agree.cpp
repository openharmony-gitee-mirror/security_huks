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

#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace {
class HksCryptoHalDhAgree : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalDhAgree_001
 * @tc.name      : HksCryptoHalDhAgree_001
 * @tc.desc      : Using HksCryptoHalAgreeKey Agree DH-2048 key.
 */
HWTEST_F(HksCryptoHalDhAgree, HksCryptoHalDhAgree_001, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_DH,
        .keyLen = HKS_DH_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob alise = { .size = 0, .data = nullptr };
    HksBlob bob = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &alise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &bob), HKS_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };
    struct HksBlob pubKeyBob = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&alise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGetPubKey(&bob, &pubKeyBob), HKS_SUCCESS);

    struct HksBlob agreeKeyAlise = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };
    struct HksBlob agreeKeyBob = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };

    EXPECT_EQ(HksCryptoHalAgreeKey(&alise, &pubKeyBob, &spec, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalAgreeKey(&bob, &pubKeyAlise, &spec, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFree(alise.data);
    HksFree(bob.data);
    HksFree(pubKeyAlise.data);
    HksFree(pubKeyBob.data);
    HksFree(agreeKeyAlise.data);
    HksFree(agreeKeyBob.data);
}

/**
 * @tc.number    : HksCryptoHalDhAgree_002
 * @tc.name      : HksCryptoHalDhAgree_002
 * @tc.desc      : Using HksCryptoHalAgreeKey Agree DH-3072 key.
 */
HWTEST_F(HksCryptoHalDhAgree, HksCryptoHalDhAgree_002, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_DH,
        .keyLen = HKS_DH_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob alise = { .size = 0, .data = nullptr };
    HksBlob bob = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &alise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &bob), HKS_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };
    struct HksBlob pubKeyBob = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&alise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGetPubKey(&bob, &pubKeyBob), HKS_SUCCESS);

    struct HksBlob agreeKeyAlise = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };
    struct HksBlob agreeKeyBob = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };

    EXPECT_EQ(HksCryptoHalAgreeKey(&alise, &pubKeyBob, &spec, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalAgreeKey(&bob, &pubKeyAlise, &spec, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFree(alise.data);
    HksFree(bob.data);
    HksFree(pubKeyAlise.data);
    HksFree(pubKeyBob.data);
    HksFree(agreeKeyAlise.data);
    HksFree(agreeKeyBob.data);
}

/**
 * @tc.number    : HksCryptoHalDhAgree_003
 * @tc.name      : HksCryptoHalDhAgree_003
 * @tc.desc      : Using HksCryptoHalAgreeKey Agree DH-4096 key.
 */
HWTEST_F(HksCryptoHalDhAgree, HksCryptoHalDhAgree_003, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_DH,
        .keyLen = HKS_DH_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob alise = { .size = 0, .data = nullptr };
    HksBlob bob = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &alise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &bob), HKS_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };
    struct HksBlob pubKeyBob = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&alise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGetPubKey(&bob, &pubKeyBob), HKS_SUCCESS);

    struct HksBlob agreeKeyAlise = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };
    struct HksBlob agreeKeyBob = { .size = 4096, .data = (uint8_t *)HksMalloc(4096) };

    EXPECT_EQ(HksCryptoHalAgreeKey(&alise, &pubKeyBob, &spec, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalAgreeKey(&bob, &pubKeyAlise, &spec, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFree(alise.data);
    HksFree(bob.data);
    HksFree(pubKeyAlise.data);
    HksFree(pubKeyBob.data);
    HksFree(agreeKeyAlise.data);
    HksFree(agreeKeyBob.data);
}
}  // namespace
#endif