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
class HksEccKeyMtTest : public testing::Test {};

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest00100
 * @tc.name      : HksEccKeyMtTest00100
 * @tc.desc      : Huks generates ECC224 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-NONE algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest00100, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_224, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_224) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest00200
 * @tc.name      : HksEccKeyMtTest00200
 * @tc.desc      : Huks generates ECC224 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA1 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest00200, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_224, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_224) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest00300
 * @tc.name      : HksEccKeyMtTest00300
 * @tc.desc      : Huks generates ECC224 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA224 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest00300, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_224, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_224) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest00400
 * @tc.name      : HksEccKeyMtTest00400
 * @tc.desc      : Huks generates ECC224 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA256 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest00400, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_224, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_224) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest00500
 * @tc.name      : HksEccKeyMtTest00500
 * @tc.desc      : Huks generates ECC224 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA384 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest00500, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_224, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_224) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest00600
 * @tc.name      : HksEccKeyMtTest00600
 * @tc.desc      : Huks generates ECC224 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA512 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest00600, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_224, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_224) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest00700
 * @tc.name      : HksEccKeyMtTest00700
 * @tc.desc      : Huks generates ECC256 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-NONE algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest00700, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_256, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_256) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest00800
 * @tc.name      : HksEccKeyMtTest00800
 * @tc.desc      : Huks generates ECC256 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA1 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest00800, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_256, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_256) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest00900
 * @tc.name      : HksEccKeyMtTest00900
 * @tc.desc      : Huks generates ECC256 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA224 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest00900, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_256, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_256) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01000
 * @tc.name      : HksEccKeyMtTest01000
 * @tc.desc      : Huks generates ECC256 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA256 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01000, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_256, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_256) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01100
 * @tc.name      : HksEccKeyMtTest01100
 * @tc.desc      : Huks generates ECC256 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA384 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01100, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_256, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_256) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01200
 * @tc.name      : HksEccKeyMtTest01200
 * @tc.desc      : Huks generates ECC256 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA512 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01200, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_256, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_256) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01300
 * @tc.name      : HksEccKeyMtTest01300
 * @tc.desc      : Huks generates ECC384 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-NONE algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01300, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_384, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_384) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01400
 * @tc.name      : HksEccKeyMtTest01400
 * @tc.desc      : Huks generates ECC384 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA1 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01400, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_384, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_384) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01500
 * @tc.name      : HksEccKeyMtTest01500
 * @tc.desc      : Huks generates ECC384 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA224 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01500, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_384, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_384) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01600
 * @tc.name      : HksEccKeyMtTest01600
 * @tc.desc      : Huks generates ECC384 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA256 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01600, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_384, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_384) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01700
 * @tc.name      : HksEccKeyMtTest01700
 * @tc.desc      : Huks generates ECC384 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA384 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01700, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_384, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_384) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01800
 * @tc.name      : HksEccKeyMtTest01800
 * @tc.desc      : Huks generates ECC384 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA512 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01800, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_384, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_384) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest01900
 * @tc.name      : HksEccKeyMtTest01900
 * @tc.desc      : Huks generates ECC521 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-NONE algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest01900, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_521, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_521) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest02000
 * @tc.name      : HksEccKeyMtTest02000
 * @tc.desc      : Huks generates ECC521 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA1 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest02000, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_521, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_521) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest02100
 * @tc.name      : HksEccKeyMtTest02100
 * @tc.desc      : Huks generates ECC521 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA224 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest02100, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_521, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_521) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest02200
 * @tc.name      : HksEccKeyMtTest02200
 * @tc.desc      : Huks generates ECC521 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA256 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest02200, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_521, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_521) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest02300
 * @tc.name      : HksEccKeyMtTest02300
 * @tc.desc      : Huks generates ECC521 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA384 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest02300, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_521, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_521) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccKeyMtTest.HksEccKeyMtTest02400
 * @tc.name      : HksEccKeyMtTest02400
 * @tc.desc      : Huks generates ECC521 bit key, which can be successfully used for OpenSSL sign/verify using
 * ECC/DIGEST-SHA512 algorithm
 */
HWTEST_F(HksEccKeyMtTest, HksEccKeyMtTest02400, TestSize.Level1)
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

    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = HKS_ECC_KEY_SIZE_521, .data = (uint8_t *)malloc(HKS_ECC_KEY_SIZE_521) } };
    HksAddParams(paramOutSet, &localKey, 1);

    HksBuildParamSet(&paramOutSet);

    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramOutSet), HKS_SUCCESS);
    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    HksBlob priKey = { .size = priParam->blob.size, .data = (uint8_t *)malloc(priParam->blob.size) };
    (void)memcpy_s(priKey.data, priParam->blob.size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    HksBlob pubKey = { .size = pubParam->blob.size, .data = (uint8_t *)malloc(pubParam->blob.size) };
    (void)memcpy_s(pubKey.data, pubParam->blob.size, pubParam->blob.data, pubParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&priKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(EcdsaVerify(&pubKey, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(localKey.blob.data);
    HksFreeParamSet(&paramOutSet);
    free(priKey.data);
    free(pubKey.data);
    free(signature.data);
}
}  // namespace