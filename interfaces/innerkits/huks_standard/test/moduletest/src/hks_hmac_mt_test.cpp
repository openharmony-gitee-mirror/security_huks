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

#include "hks_openssl_hmac_mt_test.h"

#include <gtest/gtest.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"

using namespace testing::ext;
namespace {
namespace {
const char HMAC_KEY[] = "This is a HMAC key";
}  // namespace
class HksHmacMtTest : public testing::Test {};

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest00100
 * @tc.name      : HksHmacMtTest00100
 * @tc.desc      : huks generates HMAC key, which can be successfully used for OpenSSL using HMAC-SHA1 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest00100, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = {
        .tag = HKS_TAG_SYMMETRIC_KEY_DATA, .blob = {.size = HMAC_KEY_SIZE, .data = (uint8_t *)malloc(HMAC_KEY_SIZE)}};
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);

    HksParam *outParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_SYMMETRIC_KEY_DATA, &outParam);

    HksBlob key = {.size = outParam->blob.size, .data = (uint8_t *)malloc(outParam->blob.size)};
    (void)memcpy_s(key.data, outParam->blob.size, outParam->blob.data, outParam->blob.size);

    EXPECT_EQ(HmacHmac(&key, HKS_DIGEST_SHA1, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&key, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    HksFreeParamSet(&paramOutSet);
    free(localKey.blob.data);
    free(macMessage.data);
    free(macForHuks.data);
    free(key.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest00200
 * @tc.name      : HksHmacMtTest00200
 * @tc.desc      : huks generates HMAC key, which can be successfully used for OpenSSL using HMAC-SHA224 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest00200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = {
        .tag = HKS_TAG_SYMMETRIC_KEY_DATA, .blob = {.size = HMAC_KEY_SIZE, .data = (uint8_t *)malloc(HMAC_KEY_SIZE)}};
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);

    HksParam *outParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_SYMMETRIC_KEY_DATA, &outParam);

    HksBlob key = {.size = outParam->blob.size, .data = (uint8_t *)malloc(outParam->blob.size)};
    (void)memcpy_s(key.data, outParam->blob.size, outParam->blob.data, outParam->blob.size);

    EXPECT_EQ(HmacHmac(&key, HKS_DIGEST_SHA224, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&key, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    HksFreeParamSet(&paramOutSet);
    free(localKey.blob.data);
    free(macMessage.data);
    free(macForHuks.data);
    free(key.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest00300
 * @tc.name      : HksHmacMtTest00300
 * @tc.desc      : huks generates HMAC key, which can be successfully used for OpenSSL using HMAC-SHA256 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest00300, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = {
        .tag = HKS_TAG_SYMMETRIC_KEY_DATA, .blob = {.size = HMAC_KEY_SIZE, .data = (uint8_t *)malloc(HMAC_KEY_SIZE)}};
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);

    HksParam *outParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_SYMMETRIC_KEY_DATA, &outParam);

    HksBlob key = {.size = outParam->blob.size, .data = (uint8_t *)malloc(outParam->blob.size)};
    (void)memcpy_s(key.data, outParam->blob.size, outParam->blob.data, outParam->blob.size);

    EXPECT_EQ(HmacHmac(&key, HKS_DIGEST_SHA256, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&key, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    HksFreeParamSet(&paramOutSet);
    free(localKey.blob.data);
    free(macMessage.data);
    free(macForHuks.data);
    free(key.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest00400
 * @tc.name      : HksHmacMtTest00400
 * @tc.desc      : huks generates HMAC key, which can be successfully used for OpenSSL using HMAC-SHA384 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest00400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = {
        .tag = HKS_TAG_SYMMETRIC_KEY_DATA, .blob = {.size = HMAC_KEY_SIZE, .data = (uint8_t *)malloc(HMAC_KEY_SIZE)}};
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);

    HksParam *outParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_SYMMETRIC_KEY_DATA, &outParam);

    HksBlob key = {.size = outParam->blob.size, .data = (uint8_t *)malloc(outParam->blob.size)};
    (void)memcpy_s(key.data, outParam->blob.size, outParam->blob.data, outParam->blob.size);

    EXPECT_EQ(HmacHmac(&key, HKS_DIGEST_SHA384, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&key, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    HksFreeParamSet(&paramOutSet);
    free(localKey.blob.data);
    free(macMessage.data);
    free(macForHuks.data);
    free(key.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest00500
 * @tc.name      : HksHmacMtTest00500
 * @tc.desc      : huks generates HMAC key, which can be successfully used for OpenSSL using HMAC-SHA512 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest00500, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = {
        .tag = HKS_TAG_SYMMETRIC_KEY_DATA, .blob = {.size = HMAC_KEY_SIZE, .data = (uint8_t *)malloc(HMAC_KEY_SIZE)}};
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);

    HksParam *outParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_SYMMETRIC_KEY_DATA, &outParam);

    HksBlob key = {.size = outParam->blob.size, .data = (uint8_t *)malloc(outParam->blob.size)};
    (void)memcpy_s(key.data, outParam->blob.size, outParam->blob.data, outParam->blob.size);

    EXPECT_EQ(HmacHmac(&key, HKS_DIGEST_SHA512, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&key, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    HksFreeParamSet(&paramOutSet);
    free(localKey.blob.data);
    free(macMessage.data);
    free(macForHuks.data);
    free(key.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest00600
 * @tc.name      : HksHmacMtTest00600
 * @tc.desc      : OpenSSL generates HMAC key, which can be successfully used for huks using HMAC-SHA1 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest00600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HmacGenerateKey(HMAC_KEY_SIZE, &authId), HMAC_SUCCESS);

    EXPECT_EQ(HmacHmac(&authId, HKS_DIGEST_SHA1, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macMessage.data);
    free(macForHuks.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest00700
 * @tc.name      : HksHmacMtTest00700
 * @tc.desc      : OpenSSL generates HMAC key, which can be successfully used for huks using HMAC-SHA224 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest00700, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HmacGenerateKey(HMAC_KEY_SIZE, &authId), HMAC_SUCCESS);

    EXPECT_EQ(HmacHmac(&authId, HKS_DIGEST_SHA224, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macMessage.data);
    free(macForHuks.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest00800
 * @tc.name      : HksHmacMtTest00800
 * @tc.desc      : OpenSSL generates HMAC key, which can be successfully used for huks using HMAC-SHA256 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest00800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HmacGenerateKey(HMAC_KEY_SIZE, &authId), HMAC_SUCCESS);

    EXPECT_EQ(HmacHmac(&authId, HKS_DIGEST_SHA256, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macMessage.data);
    free(macForHuks.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest00900
 * @tc.name      : HksHmacMtTest00900
 * @tc.desc      : OpenSSL generates HMAC key, which can be successfully used for huks using HMAC-SHA384 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest00900, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HmacGenerateKey(HMAC_KEY_SIZE, &authId), HMAC_SUCCESS);

    EXPECT_EQ(HmacHmac(&authId, HKS_DIGEST_SHA384, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macMessage.data);
    free(macForHuks.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest01000
 * @tc.name      : HksHmacMtTest01000
 * @tc.desc      : OpenSSL generates HMAC key, which can be successfully used for huks using HMAC-SHA512 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest01000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macMessage = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HmacGenerateKey(HMAC_KEY_SIZE, &authId), HMAC_SUCCESS);

    EXPECT_EQ(HmacHmac(&authId, HKS_DIGEST_SHA512, &message, &macMessage), HMAC_SUCCESS);
    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    EXPECT_EQ(macMessage.size, macForHuks.size);
    EXPECT_EQ(HksMemCmp(macMessage.data, macForHuks.data, macForHuks.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macMessage.data);
    free(macForHuks.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest01100
 * @tc.name      : HksHmacMtTest01100
 * @tc.desc      : huks generates HMAC key, which can be successfully used for huks using HMAC-SHA1 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest01100, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macForHuks.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest01200
 * @tc.name      : HksHmacMtTest01200
 * @tc.desc      : huks generates HMAC key, which can be successfully used for huks using HMAC-SHA224 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest01200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macForHuks.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest01300
 * @tc.name      : HksHmacMtTest01300
 * @tc.desc      : huks generates HMAC key, which can be successfully used for huks using HMAC-SHA256 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest01300, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macForHuks.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest01400
 * @tc.name      : HksHmacMtTest01400
 * @tc.desc      : huks generates HMAC key, which can be successfully used for huks using HMAC-SHA384 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest01400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macForHuks.data);
}

/**
 * @tc.number    : HksHmacMtTest.HksHmacMtTest01500
 * @tc.name      : HksHmacMtTest01500
 * @tc.desc      : huks generates HMAC key, which can be successfully used for huks using HMAC-SHA512 hash operation
 */
HWTEST_F(HksHmacMtTest, HksHmacMtTest01500, TestSize.Level1)
{
    struct HksBlob authId = {strlen(HMAC_KEY), (uint8_t *)HMAC_KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_KEY_SIZE},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = {.size = dataLen, .data = (uint8_t *)hexData};
    HksBlob macForHuks = {.size = HMAC_MESSAGE_SIZE, .data = (uint8_t *)malloc(HMAC_MESSAGE_SIZE)};

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    EXPECT_EQ(HksMac(&authId, paramInSet, &message, &macForHuks), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(macForHuks.data);
}
}  // namespace