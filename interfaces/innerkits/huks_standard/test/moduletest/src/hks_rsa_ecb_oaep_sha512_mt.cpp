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

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_openssl_rsa_test_mt.h"
#include "hks_param.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace {
namespace {
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for OAEPWithSHA-512";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
}  // namespace

class HksRsaEcbOaepSha512Mt : public testing::Test {};

static const struct HksParam RSA_18100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt18100
 * @tc.name      : HksRsaEcbOaepSha512Mt18100
 * @tc.desc      : Test huks generate key (512_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt18100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18100_PARAMS, sizeof(RSA_18100_PARAMS) / sizeof(RSA_18100_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);
    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(publicKey.data);
    free(paramSetOut);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_18200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt18200
 * @tc.name      : HksRsaEcbOaepSha512Mt18200
 * @tc.desc      : Test huks generate key (768_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt18200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18200_PARAMS, sizeof(RSA_18200_PARAMS) / sizeof(RSA_18200_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);
    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_18300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt18300
 * @tc.name      : HksRsaEcbOaepSha512Mt18300
 * @tc.desc      : Test huks generate key (1024_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt18300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18300_PARAMS, sizeof(RSA_18300_PARAMS) / sizeof(RSA_18300_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_18400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt18400
 * @tc.name      : HksRsaEcbOaepSha512Mt18400
 * @tc.desc      : Test huks generate key (2048_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt18400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18400_PARAMS, sizeof(RSA_18400_PARAMS) / sizeof(RSA_18400_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = {.size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size)};
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_18500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt18500
 * @tc.name      : HksRsaEcbOaepSha512Mt18500
 * @tc.desc      : Test huks generate key (3072_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt18500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18500_PARAMS, sizeof(RSA_18500_PARAMS) / sizeof(RSA_18500_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = {.size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size)};
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_18600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt18600
 * @tc.name      : HksRsaEcbOaepSha512Mt18600
 * @tc.desc      : Test huks generate key (4096_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt18600, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18600_PARAMS, sizeof(RSA_18600_PARAMS) / sizeof(RSA_18600_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = {.size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size)};
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_18700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt18700
 * @tc.name      : HksRsaEcbOaepSha512Mt18700
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt18700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18700_PARAMS, sizeof(RSA_18700_PARAMS) / sizeof(RSA_18700_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_INVALID_KEY_FILE);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_18800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt18800
 * @tc.name      : HksRsaEcbOaepSha512Mt18800
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt18800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18800_PARAMS, sizeof(RSA_18800_PARAMS) / sizeof(RSA_18800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = {.size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096)};
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = {0, NULL};

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_512);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_512, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_INVALID_KEY_FILE);

    EVP_PKEY_free(pkey);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_18900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt18900
 * @tc.name      : HksRsaEcbOaepSha512Mt18900
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt18900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18900_PARAMS, sizeof(RSA_18900_PARAMS) / sizeof(RSA_18900_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_INVALID_KEY_FILE);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19000
 * @tc.name      : HksRsaEcbOaepSha512Mt19000
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19000_PARAMS, sizeof(RSA_19000_PARAMS) / sizeof(RSA_19000_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = {.size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096)};
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = {0, NULL};

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_768);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_768, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_INVALID_KEY_FILE);

    EVP_PKEY_free(pkey);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19100
 * @tc.name      : HksRsaEcbOaepSha512Mt19100
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19100_PARAMS, sizeof(RSA_19100_PARAMS) / sizeof(RSA_19100_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_INVALID_KEY_FILE);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19200
 * @tc.name      : HksRsaEcbOaepSha512Mt19200
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19200_PARAMS, sizeof(RSA_19200_PARAMS) / sizeof(RSA_19200_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = {.size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096)};
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = {0, NULL};

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_1024);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_1024, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_INVALID_KEY_FILE);

    EVP_PKEY_free(pkey);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19300
 * @tc.name      : HksRsaEcbOaepSha512Mt19300
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19300_PARAMS, sizeof(RSA_19300_PARAMS) / sizeof(RSA_19300_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = {.size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size)};
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19400
 * @tc.name      : HksRsaEcbOaepSha512Mt19400
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19400_PARAMS, sizeof(RSA_19400_PARAMS) / sizeof(RSA_19400_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = {.size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096)};
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = {0, NULL};

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_2048);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_2048, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19500
 * @tc.name      : HksRsaEcbOaepSha512Mt19500
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19500_PARAMS, sizeof(RSA_19500_PARAMS) / sizeof(RSA_19500_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = {.size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size)};
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19600
 * @tc.name      : HksRsaEcbOaepSha512Mt19600
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19600_PARAMS, sizeof(RSA_19600_PARAMS) / sizeof(RSA_19600_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = {.size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096)};
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = {0, NULL};

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_3072);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_3072, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19700
 * @tc.name      : HksRsaEcbOaepSha512Mt19700
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19700_PARAMS, sizeof(RSA_19700_PARAMS) / sizeof(RSA_19700_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = {.size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size)};
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19800
 * @tc.name      : HksRsaEcbOaepSha512Mt19800
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19800_PARAMS, sizeof(RSA_19800_PARAMS) / sizeof(RSA_19800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = {.size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096)};
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = {0, NULL};

    EVP_PKEY *pkey = GenerateRSAKey(SET_SIZE_4096);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, SET_SIZE_4096, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_19900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt19900
 * @tc.name      : HksRsaEcbOaepSha512Mt19900
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt19900, TestSize.Level1)

{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_19900_PARAMS, sizeof(RSA_19900_PARAMS) / sizeof(RSA_19900_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20000
 * @tc.name      : HksRsaEcbOaepSha512Mt20000
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20000_PARAMS, sizeof(RSA_20000_PARAMS) / sizeof(RSA_20000_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = {opensslRsaKeyLen, opensslRsaKey};
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = {rsaPublicKeyLen, rsaPublicKey};
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = {.size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size)};
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20100
 * @tc.name      : HksRsaEcbOaepSha512Mt20100
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20100_PARAMS, sizeof(RSA_20100_PARAMS) / sizeof(RSA_20100_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20200
 * @tc.name      : HksRsaEcbOaepSha512Mt20200
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20200_PARAMS, sizeof(RSA_20200_PARAMS) / sizeof(RSA_20200_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = {opensslRsaKeyLen, opensslRsaKey};
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = {rsaPublicKeyLen, rsaPublicKey};
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = {.size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size)};
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20300
 * @tc.name      : HksRsaEcbOaepSha512Mt20300
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20300_PARAMS, sizeof(RSA_20300_PARAMS) / sizeof(RSA_20300_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20400
 * @tc.name      : HksRsaEcbOaepSha512Mt20400
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20400_PARAMS, sizeof(RSA_20400_PARAMS) / sizeof(RSA_20400_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = {opensslRsaKeyLen, opensslRsaKey};
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = {rsaPublicKeyLen, rsaPublicKey};
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = {.size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size)};
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20500
 * @tc.name      : HksRsaEcbOaepSha512Mt20500
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20500_PARAMS, sizeof(RSA_20500_PARAMS) / sizeof(RSA_20500_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = {.size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size)};
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20600
 * @tc.name      : HksRsaEcbOaepSha512Mt20600
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20600_PARAMS, sizeof(RSA_20600_PARAMS) / sizeof(RSA_20600_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = {opensslRsaKeyLen, opensslRsaKey};
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = {rsaPublicKeyLen, rsaPublicKey};
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = {.size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size)};
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);
    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20700
 * @tc.name      : HksRsaEcbOaepSha512Mt20700
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20700_PARAMS, sizeof(RSA_20700_PARAMS) / sizeof(RSA_20700_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = {.size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size)};
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20800
 * @tc.name      : HksRsaEcbOaepSha512Mt20800
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20800_PARAMS, sizeof(RSA_20800_PARAMS) / sizeof(RSA_20800_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = {opensslRsaKeyLen, opensslRsaKey};
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = {rsaPublicKeyLen, rsaPublicKey};
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = {.size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size)};
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);
    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_20900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt20900
 * @tc.name      : HksRsaEcbOaepSha512Mt20900
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt20900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_20900_PARAMS, sizeof(RSA_20900_PARAMS) / sizeof(RSA_20900_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = {.size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size)};
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = {.size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size)};
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_21000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha512Mt21000
 * @tc.name      : HksRsaEcbOaepSha512Mt21000
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/OAEPWithSHA-512AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha512Mt, HksRsaEcbOaepSha512Mt21000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_21000_PARAMS, sizeof(RSA_21000_PARAMS) / sizeof(RSA_21000_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = {opensslRsaKeyLen, opensslRsaKey};
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = {rsaPublicKeyLen, rsaPublicKey};
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = {.size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size)};
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA512), 0);
    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace