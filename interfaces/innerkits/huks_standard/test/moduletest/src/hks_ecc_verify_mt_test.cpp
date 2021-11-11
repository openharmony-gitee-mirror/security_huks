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
const char PUB_KEY[] = "This is a public key";
}  // namespace
class HksEccVerifyMtTest : public testing::Test {};

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest00100
 * @tc.name      : HksEccVerifyMtTest00100
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-NONE algorithm, and huks uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest00100, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest00200
 * @tc.name      : HksEccVerifyMtTest00200
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA1 algorithm, and huks uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest00200, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest00300
 * @tc.name      : HksEccVerifyMtTest00300
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA224 algorithm, and huks uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest00300, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest00400
 * @tc.name      : HksEccVerifyMtTest00400
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA256 algorithm, and huks uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest00400, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest00500
 * @tc.name      : HksEccVerifyMtTest00500
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA384 algorithm, and huks uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest00500, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest00600
 * @tc.name      : HksEccVerifyMtTest00600
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA512 algorithm, and huks uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest00600, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest00700
 * @tc.name      : HksEccVerifyMtTest00700
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-NONE algorithm, and huks uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest00700, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest00800
 * @tc.name      : HksEccVerifyMtTest00800
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA1 algorithm, and huks uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest00800, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest00900
 * @tc.name      : HksEccVerifyMtTest00900
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA224 algorithm, and huks uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest00900, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01000
 * @tc.name      : HksEccVerifyMtTest01000
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA256 algorithm, and huks uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01000, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01100
 * @tc.name      : HksEccVerifyMtTest01100
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA384 algorithm, and huks uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01100, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01200
 * @tc.name      : HksEccVerifyMtTest01200
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA512 algorithm, and huks uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01200, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01300
 * @tc.name      : HksEccVerifyMtTest01300
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-NONE algorithm, and huks uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01300, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01400
 * @tc.name      : HksEccVerifyMtTest01400
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA1 algorithm, and huks uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01400, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01500
 * @tc.name      : HksEccVerifyMtTest01500
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA224 algorithm, and huks uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01500, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01600
 * @tc.name      : HksEccVerifyMtTest01600
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA256 algorithm, and huks uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01600, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01700
 * @tc.name      : HksEccVerifyMtTest01700
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA384 algorithm, and huks uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01700, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01800
 * @tc.name      : HksEccVerifyMtTest01800
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA512 algorithm, and huks uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01800, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest01900
 * @tc.name      : HksEccVerifyMtTest01900
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-NONE algorithm, and huks uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest01900, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02000
 * @tc.name      : HksEccVerifyMtTest02000
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA1 algorithm, and huks uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02000, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02100
 * @tc.name      : HksEccVerifyMtTest02100
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA224 algorithm, and huks uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02100, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02200
 * @tc.name      : HksEccVerifyMtTest02200
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA256 algorithm, and huks uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02200, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02300
 * @tc.name      : HksEccVerifyMtTest02300
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA384 algorithm, and huks uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02300, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02400
 * @tc.name      : HksEccVerifyMtTest02400
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA512 algorithm, and huks uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02400, TestSize.Level1)
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

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&authId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02500
 * @tc.name      : HksEccVerifyMtTest02500
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-NONE algorithm, and huks uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02600
 * @tc.name      : HksEccVerifyMtTest02600
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA1 algorithm, and huks uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02700
 * @tc.name      : HksEccVerifyMtTest02700
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA224 algorithm, and huks uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02800
 * @tc.name      : HksEccVerifyMtTest02800
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA256 algorithm, and huks uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest02900
 * @tc.name      : HksEccVerifyMtTest02900
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA384 algorithm, and huks uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest02900, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03000
 * @tc.name      : HksEccVerifyMtTest03000
 * @tc.desc      : OpenSSL generates an ecc224 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA512 algorithm, and huks uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_224KEY), (uint8_t *)ECC_224KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03100
 * @tc.name      : HksEccVerifyMtTest03100
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-NONE algorithm, and huks uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03100, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03200
 * @tc.name      : HksEccVerifyMtTest03200
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA1 algorithm, and huks uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03300
 * @tc.name      : HksEccVerifyMtTest03300
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA224 algorithm, and huks uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03400
 * @tc.name      : HksEccVerifyMtTest03400
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA256 algorithm, and huks uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03500
 * @tc.name      : HksEccVerifyMtTest03500
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA384 algorithm, and huks uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03600
 * @tc.name      : HksEccVerifyMtTest03600
 * @tc.desc      : OpenSSL generates an ecc256 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA512 algorithm, and huks uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_256KEY), (uint8_t *)ECC_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03700
 * @tc.name      : HksEccVerifyMtTest03700
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-NONE algorithm, and huks uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03800
 * @tc.name      : HksEccVerifyMtTest03800
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA1 algorithm, and huks uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest03900
 * @tc.name      : HksEccVerifyMtTest03900
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA224 algorithm, and huks uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest03900, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest04000
 * @tc.name      : HksEccVerifyMtTest04000
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA256 algorithm, and huks uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest04000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest04100
 * @tc.name      : HksEccVerifyMtTest04100
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA384 algorithm, and huks uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest04100, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest04200
 * @tc.name      : HksEccVerifyMtTest04200
 * @tc.desc      : OpenSSL generates an ecc384 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA512 algorithm, and huks uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest04200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_384KEY), (uint8_t *)ECC_384KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest04300
 * @tc.name      : HksEccVerifyMtTest04300
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-NONE algorithm, and huks uses ECC/DIGEST-NONE algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest04300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_NONE, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest04400
 * @tc.name      : HksEccVerifyMtTest04400
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA1 algorithm, and huks uses ECC/DIGEST-SHA1 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest04400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA1, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest04500
 * @tc.name      : HksEccVerifyMtTest04500
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA224 algorithm, and huks uses ECC/DIGEST-SHA224 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest04500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA224, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest04600
 * @tc.name      : HksEccVerifyMtTest04600
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA256 algorithm, and huks uses ECC/DIGEST-SHA256 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest04600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA256, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest04700
 * @tc.name      : HksEccVerifyMtTest04700
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA384 algorithm, and huks uses ECC/DIGEST-SHA384 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest04700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA384, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}

/**
 * @tc.number    : HksEccVerifyMtTest.HksEccVerifyMtTest04800
 * @tc.name      : HksEccVerifyMtTest04800
 * @tc.desc      : OpenSSL generates an ecc521 bit key, which can be successfully used for OpenSSL signing with
 * ECC/DIGEST-SHA512 algorithm, and huks uses ECC/DIGEST-SHA512 algorithm for verification
 */
HWTEST_F(HksEccVerifyMtTest, HksEccVerifyMtTest04800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(ECC_521KEY), (uint8_t *)ECC_521KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &authId), ECC_SUCCESS);

    struct HksBlob pubKey = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&authId, &pubKey), ECC_SUCCESS);

    HksBlob x509Key = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKey, &x509Key), ECC_SUCCESS);
    struct HksBlob pubId = { strlen(PUB_KEY), (uint8_t *)PUB_KEY };
    EXPECT_EQ(HksImportKey(&pubId, paramInSet, &x509Key), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob message = { .size = dataLen, .data = (uint8_t *)hexData };
    HksBlob signature = { .size = ECC_MESSAGE_SIZE, .data = (uint8_t *)malloc(ECC_MESSAGE_SIZE) };

    EXPECT_EQ(EcdsaSign(&authId, HKS_DIGEST_SHA512, &message, &signature), ECC_SUCCESS);
    EXPECT_EQ(HksVerify(&pubId, paramInSet, &message, &signature), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKey.data);
    free(x509Key.data);
    free(signature.data);
}
}  // namespace