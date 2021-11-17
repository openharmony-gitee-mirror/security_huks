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
#include "hks_openssl_dh_mt_test.h"

#include <gtest/gtest.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"

using namespace testing::ext;
namespace {
namespace {
const char ALISE_KEY[] = "This is a alise key";
const char BOB_KEY[] = "This is a bob key";

int32_t LocalHksGenerate(const uint32_t keyLen, const struct HksBlob *authId, const struct HksParamSet *paramSetIn,
    struct HksBlob *priKey, struct HksBlob *pubKey)
{
    struct HksParamSet *paramOutSet = NULL;
    HksInitParamSet(&paramOutSet);
    if (keyLen == 0) {
        return HKS_FAILURE;
    }

    uint8_t *localData = (uint8_t *)HksMalloc(keyLen);
    if (localData == NULL) {
        return HKS_FAILURE;
    }
    struct HksParam localKey = { .tag = HKS_TAG_SYMMETRIC_KEY_DATA, .blob = { .size = keyLen, .data = localData } };
    HksAddParams(paramOutSet, &localKey, 1);
    HksBuildParamSet(&paramOutSet);

    if (HksGenerateKey(authId, paramSetIn, paramOutSet) != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    HksParam *priParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priParam);
    priKey->size = priParam->blob.size;
    (void)memcpy_s(priKey->data, priKey->size, priParam->blob.data, priParam->blob.size);

    HksParam *pubParam = NULL;
    HksGetParam(paramOutSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubParam);
    pubKey->size = pubParam->blob.size;
    (void)memcpy_s(pubKey->data, pubKey->size, pubParam->blob.data, pubParam->blob.size);

    HksFree(localData);
    HksFreeParamSet(&paramOutSet);
    return HKS_SUCCESS;
}
}  // namespace
class HksAgreeMtTest : public testing::Test {};

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest00100
 * @tc.name      : HksAgreeMtTest00100
 * @tc.desc      : Both parties use huks to generate an ecc224 bit key, which can be successfully used in OpenSSL to
 * negotiate using the ECDH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest00100, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    HksBlob priKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob priKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(LocalHksGenerate(HKS_ECC_KEY_SIZE_224, &alise, paramInSet, &priKeyAlise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(LocalHksGenerate(HKS_ECC_KEY_SIZE_224, &bob, paramInSet, &priKeyBob, &pubKeyBob), HKS_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_224, &priKeyAlise, &pubKeyBob, &agreeKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_224, &priKeyBob, &pubKeyAlise, &agreeKeyBob), ECC_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(priKeyAlise.data);
    free(priKeyBob.data);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest00200
 * @tc.name      : HksAgreeMtTest00200
 * @tc.desc      : Both parties use huks to generate an ecc256 bit key, which can be successfully used in OpenSSL to
 * negotiate using the ECDH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest00200, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    HksBlob priKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob priKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(LocalHksGenerate(HKS_ECC_KEY_SIZE_256, &alise, paramInSet, &priKeyAlise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(LocalHksGenerate(HKS_ECC_KEY_SIZE_256, &bob, paramInSet, &priKeyBob, &pubKeyBob), HKS_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_256, &priKeyAlise, &pubKeyBob, &agreeKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_256, &priKeyBob, &pubKeyAlise, &agreeKeyBob), ECC_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(priKeyAlise.data);
    free(priKeyBob.data);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest00300
 * @tc.name      : HksAgreeMtTest00300
 * @tc.desc      : Both parties use huks to generate an ecc384 bit key, which can be successfully used in OpenSSL to
 * negotiate using the ECDH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest00300, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    HksBlob priKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob priKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(LocalHksGenerate(HKS_ECC_KEY_SIZE_384, &alise, paramInSet, &priKeyAlise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(LocalHksGenerate(HKS_ECC_KEY_SIZE_384, &bob, paramInSet, &priKeyBob, &pubKeyBob), HKS_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_384, &priKeyAlise, &pubKeyBob, &agreeKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_384, &priKeyBob, &pubKeyAlise, &agreeKeyBob), ECC_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(priKeyAlise.data);
    free(priKeyBob.data);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest00400
 * @tc.name      : HksAgreeMtTest00400
 * @tc.desc      : Both parties use huks to generate an ecc521 bit key, which can be successfully used in OpenSSL to
 * negotiate using the ECDH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest00400, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    HksBlob priKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob priKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(LocalHksGenerate(HKS_ECC_KEY_SIZE_521, &alise, paramInSet, &priKeyAlise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(LocalHksGenerate(HKS_ECC_KEY_SIZE_521, &bob, paramInSet, &priKeyBob, &pubKeyBob), HKS_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_521, &priKeyAlise, &pubKeyBob, &agreeKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_521, &priKeyBob, &pubKeyAlise, &agreeKeyBob), ECC_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(priKeyAlise.data);
    free(priKeyBob.data);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest00500
 * @tc.name      : HksAgreeMtTest00500
 * @tc.desc      : Both parties use OpenSSL to generate an ecc224 bit key, which can be successfully used in huks to
 * negotiate using the ECDH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest00500, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &alise), ECC_SUCCESS);
    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &bob), ECC_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    struct HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&alise, &pubKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(GetEccPubKey(&bob, &pubKeyBob), ECC_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(HksAgreeKey(paramInSet, &alise, &pubKeyBob, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &pubKeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest00600
 * @tc.name      : HksAgreeMtTest00600
 * @tc.desc      : Both parties use OpenSSL to generate an ecc256 bit key, which can be successfully used in huks to
 * negotiate using the ECDH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest00600, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &alise), ECC_SUCCESS);
    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &bob), ECC_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    struct HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&alise, &pubKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(GetEccPubKey(&bob, &pubKeyBob), ECC_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(HksAgreeKey(paramInSet, &alise, &pubKeyBob, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &pubKeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest00700
 * @tc.name      : HksAgreeMtTest00700
 * @tc.desc      : Both parties use OpenSSL to generate an ecc384 bit key, which can be successfully used in huks to
 * negotiate using the ECDH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest00700, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &alise), ECC_SUCCESS);
    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &bob), ECC_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    struct HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&alise, &pubKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(GetEccPubKey(&bob, &pubKeyBob), ECC_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(HksAgreeKey(paramInSet, &alise, &pubKeyBob, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &pubKeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest00800
 * @tc.name      : HksAgreeMtTest00800
 * @tc.desc      : Both parties use OpenSSL to generate an ecc521 bit key, which can be successfully used in huks to
 * negotiate using the ECDH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest00800, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &alise), ECC_SUCCESS);
    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &bob), ECC_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    struct HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&alise, &pubKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(GetEccPubKey(&bob, &pubKeyBob), ECC_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(HksAgreeKey(paramInSet, &alise, &pubKeyBob, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &pubKeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest00900
 * @tc.name      : HksAgreeMtTest00900
 * @tc.desc      : One party uses the key of ECC224 for openssl negotiation, and the other party uses the key of ECC224
 * for huks negotiation
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest00900, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_224, &alise), ECC_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&alise, &pubKeyAlise), ECC_SUCCESS);
    HksBlob x509KeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKeyAlise, &x509KeyAlise), ECC_SUCCESS);

    EXPECT_EQ(HksGenerateKey(&bob, paramInSet, NULL), HKS_SUCCESS);
    HksBlob x509KeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&bob, paramInSet, &x509KeyBob), HKS_SUCCESS);
    struct HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509KeyBob, &pubKeyBob), ECC_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_224, &alise, &pubKeyBob, &agreeKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &x509KeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(x509KeyAlise.data);
    free(x509KeyBob.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01000
 * @tc.name      : HksAgreeMtTest01000
 * @tc.desc      : One party uses the key of ECC256 for openssl negotiation, and the other party uses the key of ECC256
 * for huks negotiation
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01000, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_256, &alise), ECC_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&alise, &pubKeyAlise), ECC_SUCCESS);
    HksBlob x509KeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKeyAlise, &x509KeyAlise), ECC_SUCCESS);

    EXPECT_EQ(HksGenerateKey(&bob, paramInSet, NULL), HKS_SUCCESS);
    HksBlob x509KeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&bob, paramInSet, &x509KeyBob), HKS_SUCCESS);
    struct HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509KeyBob, &pubKeyBob), ECC_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_256, &alise, &pubKeyBob, &agreeKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &x509KeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(x509KeyAlise.data);
    free(x509KeyBob.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01100
 * @tc.name      : HksAgreeMtTest01100
 * @tc.desc      : One party uses the key of ECC384 for openssl negotiation, and the other party uses the key of ECC384
 * for huks negotiation
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01100, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_384, &alise), ECC_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&alise, &pubKeyAlise), ECC_SUCCESS);
    HksBlob x509KeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKeyAlise, &x509KeyAlise), ECC_SUCCESS);

    EXPECT_EQ(HksGenerateKey(&bob, paramInSet, NULL), HKS_SUCCESS);
    HksBlob x509KeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&bob, paramInSet, &x509KeyBob), HKS_SUCCESS);
    struct HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509KeyBob, &pubKeyBob), ECC_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_384, &alise, &pubKeyBob, &agreeKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &x509KeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(x509KeyAlise.data);
    free(x509KeyBob.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01200
 * @tc.name      : HksAgreeMtTest01200
 * @tc.desc      : One party uses the key of ECC521 for openssl negotiation, and the other party uses the key of ECC521
 * for huks negotiation
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01200, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(ECCGenerateKey(HKS_ECC_KEY_SIZE_521, &alise), ECC_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(GetEccPubKey(&alise, &pubKeyAlise), ECC_SUCCESS);
    HksBlob x509KeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksBlobToX509(&pubKeyAlise, &x509KeyAlise), ECC_SUCCESS);

    EXPECT_EQ(HksGenerateKey(&bob, paramInSet, NULL), HKS_SUCCESS);
    HksBlob x509KeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&bob, paramInSet, &x509KeyBob), HKS_SUCCESS);
    struct HksBlob pubKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    EXPECT_EQ(X509ToHksBlob(&x509KeyBob, &pubKeyBob), ECC_SUCCESS);

    HksBlob agreeKeyAlise = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = ECC_KEY_SIZE, .data = (uint8_t *)malloc(ECC_KEY_SIZE) };

    EXPECT_EQ(EcdhAgreeKey(HKS_ECC_KEY_SIZE_521, &alise, &pubKeyBob, &agreeKeyAlise), ECC_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &x509KeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(x509KeyAlise.data);
    free(x509KeyBob.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

#ifdef HKS_SUPPORT_DH_C
/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01300
 * @tc.name      : HksAgreeMtTest01300
 * @tc.desc      : Both parties use huks to generate an dh2048 bit key, which can be successfully used in OpenSSL to
 * negotiate using the DH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01300, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    HksBlob priKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob priKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob pubKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob pubKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(LocalHksGenerate(HKS_DH_KEY_SIZE_2048, &alise, paramInSet, &priKeyAlise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(LocalHksGenerate(HKS_DH_KEY_SIZE_2048, &bob, paramInSet, &priKeyBob, &pubKeyBob), HKS_SUCCESS);

    HksBlob agreeKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };

    EXPECT_EQ(DhAgreeKey(HKS_DH_KEY_SIZE_2048, &priKeyAlise, &pubKeyBob, &agreeKeyAlise), DH_SUCCESS);
    EXPECT_EQ(DhAgreeKey(HKS_DH_KEY_SIZE_2048, &priKeyBob, &pubKeyAlise, &agreeKeyBob), DH_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(priKeyAlise.data);
    free(priKeyBob.data);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01400
 * @tc.name      : HksAgreeMtTest01400
 * @tc.desc      : Both parties use huks to generate an dh3072 bit key, which can be successfully used in OpenSSL to
 * negotiate using the DH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01400, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_3072 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    HksBlob priKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob priKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob pubKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob pubKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(LocalHksGenerate(HKS_DH_KEY_SIZE_3072, &alise, paramInSet, &priKeyAlise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(LocalHksGenerate(HKS_DH_KEY_SIZE_3072, &bob, paramInSet, &priKeyBob, &pubKeyBob), HKS_SUCCESS);

    HksBlob agreeKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };

    EXPECT_EQ(DhAgreeKey(HKS_DH_KEY_SIZE_3072, &priKeyAlise, &pubKeyBob, &agreeKeyAlise), DH_SUCCESS);
    EXPECT_EQ(DhAgreeKey(HKS_DH_KEY_SIZE_3072, &priKeyBob, &pubKeyAlise, &agreeKeyBob), DH_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(priKeyAlise.data);
    free(priKeyBob.data);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01500
 * @tc.name      : HksAgreeMtTest01500
 * @tc.desc      : Both parties use huks to generate an dh4096 bit key, which can be successfully used in OpenSSL to
 * negotiate using the DH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01500, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_4096 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    HksBlob priKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob priKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob pubKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob pubKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(LocalHksGenerate(HKS_DH_KEY_SIZE_4096, &alise, paramInSet, &priKeyAlise, &pubKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(LocalHksGenerate(HKS_DH_KEY_SIZE_4096, &bob, paramInSet, &priKeyBob, &pubKeyBob), HKS_SUCCESS);

    HksBlob agreeKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };

    EXPECT_EQ(DhAgreeKey(HKS_DH_KEY_SIZE_4096, &priKeyAlise, &pubKeyBob, &agreeKeyAlise), DH_SUCCESS);
    EXPECT_EQ(DhAgreeKey(HKS_DH_KEY_SIZE_4096, &priKeyBob, &pubKeyAlise, &agreeKeyBob), DH_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(priKeyAlise.data);
    free(priKeyBob.data);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01600
 * @tc.name      : HksAgreeMtTest01600
 * @tc.desc      : Both parties use OpenSSL to generate an dh2048 bit key, which can be successfully used in huks to
 * negotiate using the DH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01600, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(DhGenerateKey(HKS_DH_KEY_SIZE_2048, &alise), DH_SUCCESS);
    EXPECT_EQ(DhGenerateKey(HKS_DH_KEY_SIZE_2048, &bob), DH_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    struct HksBlob pubKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhGetDhPubKey(&alise, &pubKeyAlise), DH_SUCCESS);
    EXPECT_EQ(DhGetDhPubKey(&bob, &pubKeyBob), DH_SUCCESS);

    HksBlob agreeKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };

    EXPECT_EQ(HksAgreeKey(paramInSet, &alise, &pubKeyBob, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &pubKeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01700
 * @tc.name      : HksAgreeMtTest01700
 * @tc.desc      : Both parties use OpenSSL to generate an dh3072 bit key, which can be successfully used in huks to
 * negotiate using the DH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01700, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_3072 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(DhGenerateKey(HKS_DH_KEY_SIZE_3072, &alise), DH_SUCCESS);
    EXPECT_EQ(DhGenerateKey(HKS_DH_KEY_SIZE_3072, &bob), DH_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    struct HksBlob pubKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhGetDhPubKey(&alise, &pubKeyAlise), DH_SUCCESS);
    EXPECT_EQ(DhGetDhPubKey(&bob, &pubKeyBob), DH_SUCCESS);

    HksBlob agreeKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };

    EXPECT_EQ(HksAgreeKey(paramInSet, &alise, &pubKeyBob, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &pubKeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01800
 * @tc.name      : HksAgreeMtTest01800
 * @tc.desc      : Both parties use OpenSSL to generate an dh4096 bit key, which can be successfully used in huks to
 * negotiate using the DH algorithm
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01800, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_4096 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(DhGenerateKey(HKS_DH_KEY_SIZE_4096, &alise), DH_SUCCESS);
    EXPECT_EQ(DhGenerateKey(HKS_DH_KEY_SIZE_4096, &bob), DH_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    struct HksBlob pubKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhGetDhPubKey(&alise, &pubKeyAlise), DH_SUCCESS);
    EXPECT_EQ(DhGetDhPubKey(&bob, &pubKeyBob), DH_SUCCESS);

    HksBlob agreeKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };

    EXPECT_EQ(HksAgreeKey(paramInSet, &alise, &pubKeyBob, &agreeKeyAlise), HKS_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &pubKeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest01900
 * @tc.name      : HksAgreeMtTest01900
 * @tc.desc      : One party uses the key of dh2048 for openssl negotiation, and the other party uses the key of dh2048
 * for huks negotiation
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest01900, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(DhGenerateKey(HKS_DH_KEY_SIZE_2048, &alise), DH_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhGetDhPubKey(&alise, &pubKeyAlise), DH_SUCCESS);
    HksBlob x509KeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhHksBlobToX509(&pubKeyAlise, &x509KeyAlise), DH_SUCCESS);

    EXPECT_EQ(HksGenerateKey(&bob, paramInSet, NULL), HKS_SUCCESS);
    HksBlob x509KeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&bob, paramInSet, &x509KeyBob), HKS_SUCCESS);
    struct HksBlob pubKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhX509ToHksBlob(&x509KeyBob, &pubKeyBob), DH_SUCCESS);

    HksBlob agreeKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };

    EXPECT_EQ(DhAgreeKey(HKS_DH_KEY_SIZE_2048, &alise, &pubKeyBob, &agreeKeyAlise), DH_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &x509KeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(x509KeyAlise.data);
    free(x509KeyBob.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest02000
 * @tc.name      : HksAgreeMtTest02000
 * @tc.desc      : One party uses the key of dh3072 for openssl negotiation, and the other party uses the key of dh2048
 * for huks negotiation
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest02000, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_3072 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(DhGenerateKey(HKS_DH_KEY_SIZE_3072, &alise), DH_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhGetDhPubKey(&alise, &pubKeyAlise), DH_SUCCESS);
    HksBlob x509KeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhHksBlobToX509(&pubKeyAlise, &x509KeyAlise), DH_SUCCESS);

    EXPECT_EQ(HksGenerateKey(&bob, paramInSet, NULL), HKS_SUCCESS);
    HksBlob x509KeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&bob, paramInSet, &x509KeyBob), HKS_SUCCESS);
    struct HksBlob pubKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhX509ToHksBlob(&x509KeyBob, &pubKeyBob), DH_SUCCESS);

    HksBlob agreeKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };

    EXPECT_EQ(DhAgreeKey(HKS_DH_KEY_SIZE_3072, &alise, &pubKeyBob, &agreeKeyAlise), DH_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &x509KeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(x509KeyAlise.data);
    free(x509KeyBob.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}

/**
 * @tc.number    : HksAgreeMtTest.HksAgreeMtTest02100
 * @tc.name      : HksAgreeMtTest02100
 * @tc.desc      : One party uses the key of dh4096 for openssl negotiation, and the other party uses the key of dh2048
 * for huks negotiation
 */
HWTEST_F(HksAgreeMtTest, HksAgreeMtTest02100, TestSize.Level1)
{
    struct HksBlob alise = { strlen(ALISE_KEY), (uint8_t *)ALISE_KEY };
    struct HksBlob bob = { strlen(BOB_KEY), (uint8_t *)BOB_KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_4096 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(DhGenerateKey(HKS_DH_KEY_SIZE_4096, &alise), DH_SUCCESS);

    struct HksBlob pubKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhGetDhPubKey(&alise, &pubKeyAlise), DH_SUCCESS);
    HksBlob x509KeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhHksBlobToX509(&pubKeyAlise, &x509KeyAlise), DH_SUCCESS);

    EXPECT_EQ(HksGenerateKey(&bob, paramInSet, NULL), HKS_SUCCESS);
    HksBlob x509KeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(HksExportPublicKey(&bob, paramInSet, &x509KeyBob), HKS_SUCCESS);
    struct HksBlob pubKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    EXPECT_EQ(DhX509ToHksBlob(&x509KeyBob, &pubKeyBob), DH_SUCCESS);

    HksBlob agreeKeyAlise = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };
    HksBlob agreeKeyBob = { .size = DH_KEY_SIZE, .data = (uint8_t *)malloc(DH_KEY_SIZE) };

    EXPECT_EQ(DhAgreeKey(HKS_DH_KEY_SIZE_4096, &alise, &pubKeyBob, &agreeKeyAlise), DH_SUCCESS);
    EXPECT_EQ(HksAgreeKey(paramInSet, &bob, &x509KeyAlise, &agreeKeyBob), HKS_SUCCESS);

    EXPECT_EQ(agreeKeyAlise.size, agreeKeyBob.size);
    EXPECT_EQ(HksMemCmp(agreeKeyAlise.data, agreeKeyBob.data, agreeKeyAlise.size), HKS_SUCCESS);

    HksFreeParamSet(&paramInSet);
    free(pubKeyAlise.data);
    free(x509KeyAlise.data);
    free(x509KeyBob.data);
    free(pubKeyBob.data);
    free(agreeKeyAlise.data);
    free(agreeKeyBob.data);
}
#endif
}  // namespace