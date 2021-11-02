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
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for OAEPWithSHA-256";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
}  // namespace

class HksRsaEcbOaepSha256Mt : public testing::Test {};

static const struct HksParam RSA_12100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt12100
 * @tc.name      : HksRsaEcbOaepSha256Mt12100
 * @tc.desc      : Test huks generate key (512_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt12100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12100_PARAMS, sizeof(RSA_12100_PARAMS) / sizeof(RSA_12100_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), RSA_FAILED);

    free(publicKey.data);
    free(paramSetOut);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_12200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt12200
 * @tc.name      : HksRsaEcbOaepSha256Mt12200
 * @tc.desc      : Test huks generate key (768_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt12200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12200_PARAMS, sizeof(RSA_12200_PARAMS) / sizeof(RSA_12200_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_12300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt12300
 * @tc.name      : HksRsaEcbOaepSha256Mt12300
 * @tc.desc      : Test huks generate key (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt12300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12300_PARAMS, sizeof(RSA_12300_PARAMS) / sizeof(RSA_12300_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_12400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt12400
 * @tc.name      : HksRsaEcbOaepSha256Mt12400
 * @tc.desc      : Test huks generate key (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt12400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12400_PARAMS, sizeof(RSA_12400_PARAMS) / sizeof(RSA_12400_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_12500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt12500
 * @tc.name      : HksRsaEcbOaepSha256Mt12500
 * @tc.desc      : Test huks generate key (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt12500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12500_PARAMS, sizeof(RSA_12500_PARAMS) / sizeof(RSA_12500_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_12600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt12600
 * @tc.name      : HksRsaEcbOaepSha256Mt12600
 * @tc.desc      : Test huks generate key (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt12600, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12600_PARAMS, sizeof(RSA_12600_PARAMS) / sizeof(RSA_12600_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_12700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt12700
 * @tc.name      : HksRsaEcbOaepSha256Mt12700
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt12700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12700_PARAMS, sizeof(RSA_12700_PARAMS) / sizeof(RSA_12700_PARAMS[0])),
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

static const struct HksParam RSA_12800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt12800
 * @tc.name      : HksRsaEcbOaepSha256Mt12800
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt12800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12800_PARAMS, sizeof(RSA_12800_PARAMS) / sizeof(RSA_12800_PARAMS[0])),
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

static const struct HksParam RSA_12900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt12900
 * @tc.name      : HksRsaEcbOaepSha256Mt12900
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt12900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12900_PARAMS, sizeof(RSA_12900_PARAMS) / sizeof(RSA_12900_PARAMS[0])),
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

    const char *hexData = "00112233445566778899";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt13000
 * @tc.name      : HksRsaEcbOaepSha256Mt13000
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13000_PARAMS, sizeof(RSA_13000_PARAMS) / sizeof(RSA_13000_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899";

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

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_768);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_768, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt13100
 * @tc.name      : HksRsaEcbOaepSha256Mt13100
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13100_PARAMS, sizeof(RSA_13100_PARAMS) / sizeof(RSA_13100_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt13200
 * @tc.name      : HksRsaEcbOaepSha256Mt13200
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13200_PARAMS, sizeof(RSA_13200_PARAMS) / sizeof(RSA_13200_PARAMS[0])),
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

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_1024);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_1024, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt13300
 * @tc.name      : HksRsaEcbOaepSha256Mt13300
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13300_PARAMS, sizeof(RSA_13300_PARAMS) / sizeof(RSA_13300_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt13400
 * @tc.name      : HksRsaEcbOaepSha256Mt13400
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13400_PARAMS, sizeof(RSA_13400_PARAMS) / sizeof(RSA_13400_PARAMS[0])),
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
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt00100
 * @tc.name      : HksRsaEcbOaepSha256Mt00100
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13500_PARAMS, sizeof(RSA_13500_PARAMS) / sizeof(RSA_13500_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt13600
 * @tc.name      : HksRsaEcbOaepSha256Mt13600
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13600_PARAMS, sizeof(RSA_13600_PARAMS) / sizeof(RSA_13600_PARAMS[0])),
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
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt13700
 * @tc.name      : HksRsaEcbOaepSha256Mt13700
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13700_PARAMS, sizeof(RSA_13700_PARAMS) / sizeof(RSA_13700_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt13800
 * @tc.name      : HksRsaEcbOaepSha256Mt13800
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13800_PARAMS, sizeof(RSA_13800_PARAMS) / sizeof(RSA_13800_PARAMS[0])),
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
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_13900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt13900
 * @tc.name      : HksRsaEcbOaepSha256Mt13900
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt13900, TestSize.Level1)

{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_13900_PARAMS, sizeof(RSA_13900_PARAMS) / sizeof(RSA_13900_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_14000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14000
 * @tc.name      : HksRsaEcbOaepSha256Mt14000
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14000_PARAMS, sizeof(RSA_14000_PARAMS) / sizeof(RSA_14000_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_14100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14100
 * @tc.name      : HksRsaEcbOaepSha256Mt14100
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14100_PARAMS, sizeof(RSA_14100_PARAMS) / sizeof(RSA_14100_PARAMS[0])),
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

    const char *hexData = "00112233445566778899";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

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

static const struct HksParam RSA_14200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14200
 * @tc.name      : HksRsaEcbOaepSha256Mt14200
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14200_PARAMS, sizeof(RSA_14200_PARAMS) / sizeof(RSA_14200_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);
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

static const struct HksParam RSA_14300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14300
 * @tc.name      : HksRsaEcbOaepSha256Mt14300
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14300_PARAMS, sizeof(RSA_14300_PARAMS) / sizeof(RSA_14300_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

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

static const struct HksParam RSA_14400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14400
 * @tc.name      : HksRsaEcbOaepSha256Mt14400
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14400_PARAMS, sizeof(RSA_14400_PARAMS) / sizeof(RSA_14400_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);
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

static const struct HksParam RSA_14500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14500
 * @tc.name      : HksRsaEcbOaepSha256Mt14500
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14500_PARAMS, sizeof(RSA_14500_PARAMS) / sizeof(RSA_14500_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

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

static const struct HksParam RSA_14600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14600
 * @tc.name      : HksRsaEcbOaepSha256Mt14600
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14600_PARAMS, sizeof(RSA_14600_PARAMS) / sizeof(RSA_14600_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);
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

static const struct HksParam RSA_14700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14700
 * @tc.name      : HksRsaEcbOaepSha256Mt14700
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14700_PARAMS, sizeof(RSA_14700_PARAMS) / sizeof(RSA_14700_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

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

static const struct HksParam RSA_14800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14800
 * @tc.name      : HksRsaEcbOaepSha256Mt14800
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14800_PARAMS, sizeof(RSA_14800_PARAMS) / sizeof(RSA_14800_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);
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

static const struct HksParam RSA_14900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt14900
 * @tc.name      : HksRsaEcbOaepSha256Mt14900
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt14900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_14900_PARAMS, sizeof(RSA_14900_PARAMS) / sizeof(RSA_14900_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);

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

static const struct HksParam RSA_15000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaEcbOaepSha256Mt15000
 * @tc.name      : HksRsaEcbOaepSha256Mt15000
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-256AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha256Mt, HksRsaEcbOaepSha256Mt15000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15000_PARAMS, sizeof(RSA_15000_PARAMS) / sizeof(RSA_15000_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA256), 0);
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