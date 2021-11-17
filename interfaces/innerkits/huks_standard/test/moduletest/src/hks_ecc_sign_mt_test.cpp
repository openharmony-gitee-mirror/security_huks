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

#include "hks_openssl_ecc_mt_test.h"

#include <gtest/gtest.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"

using namespace testing::ext;
namespace {
namespace {
const char ECC_224KEY[] = "This is a ECC_224 key";
const char ECC_256KEY[] = "This is a ECC_256 key";
const char ECC_384KEY[] = "This is a ECC_384 key";
const char ECC_521KEY[] = "This is a ECC_521 key";
}  // namespace
class HksEccSignMtTest : public testing::Test {};

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest00100
 * @tc.name      : HksEccSignMtTest00100
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-NONE algorithm, and OpenSSL uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest00100, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest00200
 * @tc.name      : HksEccSignMtTest00200
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA1 algorithm, and OpenSSL uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest00200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest00300
 * @tc.name      : HksEccSignMtTest00300
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA224 algorithm, and OpenSSL uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest00300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest00400
 * @tc.name      : HksEccSignMtTest00400
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA256 algorithm, and OpenSSL uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest00400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest00500
 * @tc.name      : HksEccSignMtTest00500
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA384 algorithm, and OpenSSL uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest00500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest00600
 * @tc.name      : HksEccSignMtTest00600
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA512 algorithm, and OpenSSL uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest00600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest00700
 * @tc.name      : HksEccSignMtTest00700
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-NONE algorithm, and OpenSSL uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest00700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest00800
 * @tc.name      : HksEccSignMtTest00800
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA1 algorithm, and OpenSSL uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest00800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest00900
 * @tc.name      : HksEccSignMtTest00900
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA224 algorithm, and OpenSSL uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest00900, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01000
 * @tc.name      : HksEccSignMtTest01000
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA256 algorithm, and OpenSSL uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01100
 * @tc.name      : HksEccSignMtTest01100
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA384 algorithm, and OpenSSL uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01100, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01200
 * @tc.name      : HksEccSignMtTest01200
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA512 algorithm, and OpenSSL uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01300
 * @tc.name      : HksEccSignMtTest01300
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-NONE algorithm, and OpenSSL uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01400
 * @tc.name      : HksEccSignMtTest01400
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA1 algorithm, and OpenSSL uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01500
 * @tc.name      : HksEccSignMtTest01500
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA224 algorithm, and OpenSSL uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01600
 * @tc.name      : HksEccSignMtTest01600
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA256 algorithm, and OpenSSL uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01700
 * @tc.name      : HksEccSignMtTest01700
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA384 algorithm, and OpenSSL uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01800
 * @tc.name      : HksEccSignMtTest01800
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA512 algorithm, and OpenSSL uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest01900
 * @tc.name      : HksEccSignMtTest01900
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-NONE algorithm, and OpenSSL uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest01900, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02000
 * @tc.name      : HksEccSignMtTest02000
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA1 algorithm, and OpenSSL uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02100
 * @tc.name      : HksEccSignMtTest02100
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA224 algorithm, and OpenSSL uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02100, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02200
 * @tc.name      : HksEccSignMtTest02200
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA256 algorithm, and OpenSSL uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02300
 * @tc.name      : HksEccSignMtTest02300
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA384 algorithm, and OpenSSL uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02400
 * @tc.name      : HksEccSignMtTest02400
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA512 algorithm, and OpenSSL uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02500
 * @tc.name      : HksEccSignMtTest02500
 * @tc.desc      : Huks generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-NONE algorithm, and OpenSSL uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02600
 * @tc.name      : HksEccSignMtTest02600
 * @tc.desc      : Huks generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA1 algorithm, and OpenSSL uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02700
 * @tc.name      : HksEccSignMtTest02700
 * @tc.desc      : Huks generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA224 algorithm, and OpenSSL uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02800
 * @tc.name      : HksEccSignMtTest02800
 * @tc.desc      : Huks generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA256 algorithm, and OpenSSL uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest02900
 * @tc.name      : HksEccSignMtTest02900
 * @tc.desc      : Huks generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA384 algorithm, and OpenSSL uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest02900, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03000
 * @tc.name      : HksEccSignMtTest03000
 * @tc.desc      : Huks generates an ecc224 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA512 algorithm, and OpenSSL uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03100
 * @tc.name      : HksEccSignMtTest03100
 * @tc.desc      : Huks generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-NONE algorithm, and OpenSSL uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03100, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03200
 * @tc.name      : HksEccSignMtTest03200
 * @tc.desc      : Huks generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA1 algorithm, and OpenSSL uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03300
 * @tc.name      : HksEccSignMtTest03300
 * @tc.desc      : Huks generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA224 algorithm, and OpenSSL uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03400
 * @tc.name      : HksEccSignMtTest03400
 * @tc.desc      : Huks generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA256 algorithm, and OpenSSL uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03500
 * @tc.name      : HksEccSignMtTest03500
 * @tc.desc      : Huks generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA384 algorithm, and OpenSSL uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03600
 * @tc.name      : HksEccSignMtTest03600
 * @tc.desc      : Huks generates an ecc256 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA512 algorithm, and OpenSSL uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03700
 * @tc.name      : HksEccSignMtTest03700
 * @tc.desc      : Huks generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-NONE algorithm, and OpenSSL uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03800
 * @tc.name      : HksEccSignMtTest03800
 * @tc.desc      : Huks generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA1 algorithm, and OpenSSL uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest03900
 * @tc.name      : HksEccSignMtTest03900
 * @tc.desc      : Huks generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA224 algorithm, and OpenSSL uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest03900, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest04000
 * @tc.name      : HksEccSignMtTest04000
 * @tc.desc      : Huks generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA256 algorithm, and OpenSSL uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest04000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest04100
 * @tc.name      : HksEccSignMtTest04100
 * @tc.desc      : Huks generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA384 algorithm, and OpenSSL uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest04100, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest04200
 * @tc.name      : HksEccSignMtTest04200
 * @tc.desc      : Huks generates an ecc384 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA512 algorithm, and OpenSSL uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest04200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest04300
 * @tc.name      : HksEccSignMtTest04300
 * @tc.desc      : Huks generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-NONE algorithm, and OpenSSL uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest04300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest04400
 * @tc.name      : HksEccSignMtTest04400
 * @tc.desc      : Huks generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA1 algorithm, and OpenSSL uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest04400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest04500
 * @tc.name      : HksEccSignMtTest04500
 * @tc.desc      : Huks generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA224 algorithm, and OpenSSL uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest04500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest04600
 * @tc.name      : HksEccSignMtTest04600
 * @tc.desc      : Huks generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA256 algorithm, and OpenSSL uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest04600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest04700
 * @tc.name      : HksEccSignMtTest04700
 * @tc.desc      : Huks generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA384 algorithm, and OpenSSL uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest04700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccSignMtTest.HksEccSignMtTest04800
 * @tc.name      : HksEccSignMtTest04800
 * @tc.desc      : Huks generates an ecc521 bit key, which can be successfully used for huks signing with
 * ECC/DIGEST-SHA512 algorithm, and OpenSSL uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccSignMtTest, HksEccSignMtTest04800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, NULL), HKS_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);
    HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509Key, &pubKey), ECC_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(HksSign(&authId, paramInSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(x509Key.data);
    free(pubKey.data);
    free(signature.data);
}
}  // namespace