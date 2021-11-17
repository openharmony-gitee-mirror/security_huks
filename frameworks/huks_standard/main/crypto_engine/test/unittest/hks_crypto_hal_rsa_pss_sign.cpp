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
class HksCryptoHalRsaPssSign : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalRsaPssSign_001
 * @tc.name      : HksCryptoHalRsaPssSign_001
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_001, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };
    usageSpec.algType = HKS_ALG_RSA;
    usageSpec.padding = HKS_PADDING_PSS;
    usageSpec.purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY;

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_002
 * @tc.name      : HksCryptoHalRsaPssSign_002
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_002, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_003
 * @tc.name      : HksCryptoHalRsaPssSign_003
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_003, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_004
 * @tc.name      : HksCryptoHalRsaPssSign_004
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_004, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_005
 * @tc.name      : HksCryptoHalRsaPssSign_005
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_005, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_006
 * @tc.name      : HksCryptoHalRsaPssSign_006
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_006, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_007
 * @tc.name      : HksCryptoHalRsaPssSign_007
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_007, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };
    usageSpec.algType = HKS_ALG_RSA;
    usageSpec.padding = HKS_PADDING_PSS;
    usageSpec.purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY;

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_008
 * @tc.name      : HksCryptoHalRsaPssSign_008
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_008, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_009
 * @tc.name      : HksCryptoHalRsaPssSign_009
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_009, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_010
 * @tc.name      : HksCryptoHalRsaPssSign_010
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_010, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_011
 * @tc.name      : HksCryptoHalRsaPssSign_011
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_011, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_012
 * @tc.name      : HksCryptoHalRsaPssSign_012
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_012, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_013
 * @tc.name      : HksCryptoHalRsaPssSign_013
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_013, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_014
 * @tc.name      : HksCryptoHalRsaPssSign_014
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_014, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_015
 * @tc.name      : HksCryptoHalRsaPssSign_015
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_015, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_016
 * @tc.name      : HksCryptoHalRsaPssSign_016
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_016, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_017
 * @tc.name      : HksCryptoHalRsaPssSign_017
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_017, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_018
 * @tc.name      : HksCryptoHalRsaPssSign_018
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_018, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_019
 * @tc.name      : HksCryptoHalRsaPssSign_019
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_019, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_ERROR_CRYPTO_ENGINE_ERROR);
    HksFree(message.data);
    HksFree(signature.data);
    HksFree(key.data);
    return;
#endif
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);
#endif

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_020
 * @tc.name      : HksCryptoHalRsaPssSign_020
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_020, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_021
 * @tc.name      : HksCryptoHalRsaPssSign_021
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_021, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_022
 * @tc.name      : HksCryptoHalRsaPssSign_022
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_022, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_023
 * @tc.name      : HksCryptoHalRsaPssSign_023
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_023, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_024
 * @tc.name      : HksCryptoHalRsaPssSign_024
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_024, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_025
 * @tc.name      : HksCryptoHalRsaPssSign_025
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_025, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_ERROR_CRYPTO_ENGINE_ERROR);
    HksFree(message.data);
    HksFree(signature.data);
    HksFree(key.data);
    return;
#endif
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);
#endif

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_026
 * @tc.name      : HksCryptoHalRsaPssSign_026
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_026, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_027
 * @tc.name      : HksCryptoHalRsaPssSign_027
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_027, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_028
 * @tc.name      : HksCryptoHalRsaPssSign_028
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_028, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_029
 * @tc.name      : HksCryptoHalRsaPssSign_029
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_029, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}
}  // namespace