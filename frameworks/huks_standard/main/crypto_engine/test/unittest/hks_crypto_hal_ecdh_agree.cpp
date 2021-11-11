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
class HksCryptoHalEcdhAgree : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalEcdhAgree_001
 * @tc.name      : HksCryptoHalEcdhAgree_001
 * @tc.desc      : Using HksCryptoHalAgreeKey Agree ECC-224 key.
 */
HWTEST_F(HksCryptoHalEcdhAgree, HksCryptoHalEcdhAgree_001, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_224,
        .algParam = nullptr,
    };

    HksBlob alise = { .size = 0, .data = nullptr };
    HksBlob bob = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &alise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &bob), HKS_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = 256, .data = (uint8_t *)HksMalloc(256) };
    struct HksBlob pubKeyBob = { .size = 256, .data = (uint8_t *)HksMalloc(256) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&alise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGetPubKey(&bob, &pubKeyBob), HKS_SUCCESS);

    struct HksBlob agreeKeyAlise = { .size = 256, .data = (uint8_t *)HksMalloc(256) };
    struct HksBlob agreeKeyBob = { .size = 256, .data = (uint8_t *)HksMalloc(256) };

    spec.algType = HKS_ALG_ECDH;

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
 * @tc.number    : HksCryptoHalEcdhAgree_002
 * @tc.name      : HksCryptoHalEcdhAgree_002
 * @tc.desc      : Using HksCryptoHalAgreeKey Agree ECC-256 key.
 */
HWTEST_F(HksCryptoHalEcdhAgree, HksCryptoHalEcdhAgree_002, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob alise = { .size = 0, .data = nullptr };
    HksBlob bob = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &alise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &bob), HKS_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = 256, .data = (uint8_t *)HksMalloc(256) };
    struct HksBlob pubKeyBob = { .size = 256, .data = (uint8_t *)HksMalloc(256) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&alise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGetPubKey(&bob, &pubKeyBob), HKS_SUCCESS);

    struct HksBlob agreeKeyAlise = { .size = 256, .data = (uint8_t *)HksMalloc(256) };
    struct HksBlob agreeKeyBob = { .size = 256, .data = (uint8_t *)HksMalloc(256) };

    spec.algType = HKS_ALG_ECDH;

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
 * @tc.number    : HksCryptoHalEcdhAgree_003
 * @tc.name      : HksCryptoHalEcdhAgree_003
 * @tc.desc      : Using HksCryptoHalAgreeKey Agree ECC-384 key.
 */
HWTEST_F(HksCryptoHalEcdhAgree, HksCryptoHalEcdhAgree_003, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_384,
        .algParam = nullptr,
    };

    HksBlob alise = { .size = 0, .data = nullptr };
    HksBlob bob = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &alise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &bob), HKS_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = 256, .data = (uint8_t *)HksMalloc(256) };
    struct HksBlob pubKeyBob = { .size = 256, .data = (uint8_t *)HksMalloc(256) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&alise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGetPubKey(&bob, &pubKeyBob), HKS_SUCCESS);

    struct HksBlob agreeKeyAlise = { .size = 256, .data = (uint8_t *)HksMalloc(256) };
    struct HksBlob agreeKeyBob = { .size = 256, .data = (uint8_t *)HksMalloc(256) };

    spec.algType = HKS_ALG_ECDH;

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
 * @tc.number    : HksCryptoHalEcdhAgree_004
 * @tc.name      : HksCryptoHalEcdhAgree_004
 * @tc.desc      : Using HksCryptoHalAgreeKey Agree ECC-521 key.
 */
HWTEST_F(HksCryptoHalEcdhAgree, HksCryptoHalEcdhAgree_004, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_521,
        .algParam = nullptr,
    };

    HksBlob alise = { .size = 0, .data = nullptr };
    HksBlob bob = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &alise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &bob), HKS_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = 256, .data = (uint8_t *)HksMalloc(256) };
    struct HksBlob pubKeyBob = { .size = 256, .data = (uint8_t *)HksMalloc(256) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&alise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksCryptoHalGetPubKey(&bob, &pubKeyBob), HKS_SUCCESS);

    struct HksBlob agreeKeyAlise = { .size = 256, .data = (uint8_t *)HksMalloc(256) };
    struct HksBlob agreeKeyBob = { .size = 256, .data = (uint8_t *)HksMalloc(256) };

    spec.algType = HKS_ALG_ECDH;

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