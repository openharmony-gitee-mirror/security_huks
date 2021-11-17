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
class HksCryptoHalEcdsaSign : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalEcdsaSign_001
 * @tc.name      : HksCryptoHalEcdsaSign_001
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-224-NONE key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_001, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_224,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_002
 * @tc.name      : HksCryptoHalEcdsaSign_002
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-256-NONE key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_002, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_003
 * @tc.name      : HksCryptoHalEcdsaSign_003
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-384-NONE key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_003, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_384,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_004
 * @tc.name      : HksCryptoHalEcdsaSign_004
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-521-NONE key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_004, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_521,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_005
 * @tc.name      : HksCryptoHalEcdsaSign_005
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-224-SHA1 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_005, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_224,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_006
 * @tc.name      : HksCryptoHalEcdsaSign_006
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-256-SHA1 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_006, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_007
 * @tc.name      : HksCryptoHalEcdsaSign_007
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-384-SHA1 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_007, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_384,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_008
 * @tc.name      : HksCryptoHalEcdsaSign_008
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-521-SHA1 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_008, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_521,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_009
 * @tc.name      : HksCryptoHalEcdsaSign_009
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-224-SHA224 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_009, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_224,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_010
 * @tc.name      : HksCryptoHalEcdsaSign_010
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-256-SHA224 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_010, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_011
 * @tc.name      : HksCryptoHalEcdsaSign_011
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-384-SHA224 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_011, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_384,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_012
 * @tc.name      : HksCryptoHalEcdsaSign_012
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-521-SHA224 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_012, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_521,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_013
 * @tc.name      : HksCryptoHalEcdsaSign_013
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-224-SHA256 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_013, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_224,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_014
 * @tc.name      : HksCryptoHalEcdsaSign_014
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-256-SHA256 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_014, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_015
 * @tc.name      : HksCryptoHalEcdsaSign_015
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-384-SHA256 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_015, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_384,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_016
 * @tc.name      : HksCryptoHalEcdsaSign_016
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-521-SHA256 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_016, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_521,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_017
 * @tc.name      : HksCryptoHalEcdsaSign_017
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-224-SHA384 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_017, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_224,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_018
 * @tc.name      : HksCryptoHalEcdsaSign_018
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-256-SHA384 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_018, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_019
 * @tc.name      : HksCryptoHalEcdsaSign_019
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-384-SHA384 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_019, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_384,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_020
 * @tc.name      : HksCryptoHalEcdsaSign_020
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-521-SHA384 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_020, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_521,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_021
 * @tc.name      : HksCryptoHalEcdsaSign_021
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-224-SHA512 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_021, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_224,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_022
 * @tc.name      : HksCryptoHalEcdsaSign_022
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-256-SHA512 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_022, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_023
 * @tc.name      : HksCryptoHalEcdsaSign_023
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-384-SHA512 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_023, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_384,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}

/**
 * @tc.number    : HksCryptoHalEcdsaSign_024
 * @tc.name      : HksCryptoHalEcdsaSign_024
 * @tc.desc      : Using HksCryptoHalSign Sign ECC-521-SHA512 key.
 */
HWTEST_F(HksCryptoHalEcdsaSign, HksCryptoHalEcdsaSign_024, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ECC,
        .keyLen = HKS_ECC_KEY_SIZE_521,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ECC,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }
    struct HksBlob signature = { .size = 521, .data = (uint8_t *)HksMalloc(521) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 218, .data = (uint8_t *)HksMalloc(218) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
    HksFree(key.data);
}
}  // namespace