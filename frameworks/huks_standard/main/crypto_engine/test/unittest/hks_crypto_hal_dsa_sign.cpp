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
class HksCryptoHalDsaSign : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalDsaSign_001
 * @tc.name      : HksCryptoHalDsaSign_001
 * @tc.desc      : Using HksCryptoHalSign Sign DSA-SHA1 key.
 */
HWTEST_F(HksCryptoHalDsaSign, HksCryptoHalDsaSign_001, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_DSA,
        .keyLen = 256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_ERROR_NOT_SUPPORTED);
    return;
#endif
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);
#endif

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_DSA,
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
    struct HksBlob signature = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(key.data);
    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
}

/**
 * @tc.number    : HksCryptoHalDsaSign_002
 * @tc.name      : HksCryptoHalDsaSign_002
 * @tc.desc      : Using HksCryptoHalSign Sign DSA-SHA224 key.
 */
HWTEST_F(HksCryptoHalDsaSign, HksCryptoHalDsaSign_002, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_DSA,
        .keyLen = 256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_ERROR_NOT_SUPPORTED);
    return;
#endif
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);
#endif

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_DSA,
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
    struct HksBlob signature = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(key.data);
    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
}

/**
 * @tc.number    : HksCryptoHalDsaSign_003
 * @tc.name      : HksCryptoHalDsaSign_003
 * @tc.desc      : Using HksCryptoHalSign Sign DSA-SHA256 key.
 */
HWTEST_F(HksCryptoHalDsaSign, HksCryptoHalDsaSign_003, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_DSA,
        .keyLen = 256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_ERROR_NOT_SUPPORTED);
    return;
#endif
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);
#endif

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_DSA,
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
    struct HksBlob signature = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(key.data);
    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
}

/**
 * @tc.number    : HksCryptoHalDsaSign_004
 * @tc.name      : HksCryptoHalDsaSign_004
 * @tc.desc      : Using HksCryptoHalSign Sign DSA-SHA384 key.
 */
HWTEST_F(HksCryptoHalDsaSign, HksCryptoHalDsaSign_004, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_DSA,
        .keyLen = 256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_ERROR_NOT_SUPPORTED);
    return;
#endif
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);
#endif

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_DSA,
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
    struct HksBlob signature = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(key.data);
    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
}

/**
 * @tc.number    : HksCryptoHalDsaSign_005
 * @tc.name      : HksCryptoHalDsaSign_005
 * @tc.desc      : Using HksCryptoHalSign Sign DSA-SHA512 key.
 */
HWTEST_F(HksCryptoHalDsaSign, HksCryptoHalDsaSign_005, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_DSA,
        .keyLen = 256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_ERROR_NOT_SUPPORTED);
    return;
#endif
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksCryptoHalGenerateKey(&spec, &key), HKS_SUCCESS);
#endif

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_DSA,
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
    struct HksBlob signature = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &message, &signature), HKS_SUCCESS);

    struct HksBlob pubKey = { .size = 1024, .data = (uint8_t *)HksMalloc(1024) };

    EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

    EXPECT_EQ(HksCryptoHalVerify(&pubKey, &usageSpec, &message, &signature), HKS_SUCCESS);

    HksFree(key.data);
    HksFree(message.data);
    HksFree(signature.data);
    HksFree(pubKey.data);
}
}  // namespace