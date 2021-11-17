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

#include "hks_openssl_rsa_test_mt.h"

#include <gtest/gtest.h>

#include "hks_api.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace {
namespace {
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for OAEPWithSHA-384";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
}  // namespace

class HksRsaEcbOaepSha384Mt : public testing::Test {};

static const struct HksParam RSA_15100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt15100
 * @tc.name      : HksRsaEcbOaepSha384Mt15100
 * @tc.desc      : Test huks generate key (512_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt15100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15100_PARAMS, sizeof(RSA_15100_PARAMS) / sizeof(RSA_15100_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);
    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), RSA_FAILED);

    free(publicKey.data);
    free(paramSetOut);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_15200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt15200
 * @tc.name      : HksRsaEcbOaepSha384Mt15200
 * @tc.desc      : Test huks generate key (768_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt15200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15200_PARAMS, sizeof(RSA_15200_PARAMS) / sizeof(RSA_15200_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);
    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_15300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt15300
 * @tc.name      : HksRsaEcbOaepSha384Mt15300
 * @tc.desc      : Test huks generate key (1024_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt15300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15300_PARAMS, sizeof(RSA_15300_PARAMS) / sizeof(RSA_15300_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_15400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt15400
 * @tc.name      : HksRsaEcbOaepSha384Mt15400
 * @tc.desc      : Test huks generate key (2048_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt15400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15400_PARAMS, sizeof(RSA_15400_PARAMS) / sizeof(RSA_15400_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_15500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt15500
 * @tc.name      : HksRsaEcbOaepSha384Mt15500
 * @tc.desc      : Test huks generate key (3072_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt15500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15500_PARAMS, sizeof(RSA_15500_PARAMS) / sizeof(RSA_15500_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_15600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt15600
 * @tc.name      : HksRsaEcbOaepSha384Mt15600
 * @tc.desc      : Test huks generate key (4096_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt15600, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15600_PARAMS, sizeof(RSA_15600_PARAMS) / sizeof(RSA_15600_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_15700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt15700
 * @tc.name      : HksRsaEcbOaepSha384Mt15700
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt15700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15700_PARAMS, sizeof(RSA_15700_PARAMS) / sizeof(RSA_15700_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_INVALID_KEY_FILE);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_15800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt15800
 * @tc.name      : HksRsaEcbOaepSha384Mt15800
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt15800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15800_PARAMS, sizeof(RSA_15800_PARAMS) / sizeof(RSA_15800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

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

static const struct HksParam RSA_15900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt15900
 * @tc.name      : HksRsaEcbOaepSha384Mt15900
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt15900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_15900_PARAMS, sizeof(RSA_15900_PARAMS) / sizeof(RSA_15900_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_INVALID_KEY_FILE);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_16000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16000
 * @tc.name      : HksRsaEcbOaepSha384Mt16000
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16000_PARAMS, sizeof(RSA_16000_PARAMS) / sizeof(RSA_16000_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

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

static const struct HksParam RSA_16100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16100
 * @tc.name      : HksRsaEcbOaepSha384Mt16100
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16100_PARAMS, sizeof(RSA_16100_PARAMS) / sizeof(RSA_16100_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_16200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16200
 * @tc.name      : HksRsaEcbOaepSha384Mt16200
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16200_PARAMS, sizeof(RSA_16200_PARAMS) / sizeof(RSA_16200_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_1024);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_1024, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_16300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16300
 * @tc.name      : HksRsaEcbOaepSha384Mt16300
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16300_PARAMS, sizeof(RSA_16300_PARAMS) / sizeof(RSA_16300_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_16400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16400
 * @tc.name      : HksRsaEcbOaepSha384Mt16400
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16400_PARAMS, sizeof(RSA_16400_PARAMS) / sizeof(RSA_16400_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_2048);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_2048, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_16500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16500
 * @tc.name      : HksRsaEcbOaepSha384Mt16500
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16500_PARAMS, sizeof(RSA_16500_PARAMS) / sizeof(RSA_16500_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_16600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16600
 * @tc.name      : HksRsaEcbOaepSha384Mt16600
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16600_PARAMS, sizeof(RSA_16600_PARAMS) / sizeof(RSA_16600_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_3072);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_3072, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_16700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16700
 * @tc.name      : HksRsaEcbOaepSha384Mt16700
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16700_PARAMS, sizeof(RSA_16700_PARAMS) / sizeof(RSA_16700_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_16800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16800
 * @tc.name      : HksRsaEcbOaepSha384Mt16800
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16800_PARAMS, sizeof(RSA_16800_PARAMS) / sizeof(RSA_16800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLen = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(SET_SIZE_4096);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, SET_SIZE_4096, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_16900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt16900
 * @tc.name      : HksRsaEcbOaepSha384Mt16900
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt16900, TestSize.Level1)

{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_16900_PARAMS, sizeof(RSA_16900_PARAMS) / sizeof(RSA_16900_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_17000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17000
 * @tc.name      : HksRsaEcbOaepSha384Mt17000
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17000_PARAMS, sizeof(RSA_17000_PARAMS) / sizeof(RSA_17000_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = { opensslRsaKeyLen, opensslRsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = { rsaPublicKeyLen, rsaPublicKey };
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = { .size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_17100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17100
 * @tc.name      : HksRsaEcbOaepSha384Mt17100
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17100_PARAMS, sizeof(RSA_17100_PARAMS) / sizeof(RSA_17100_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_17200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17200
 * @tc.name      : HksRsaEcbOaepSha384Mt17200
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17200_PARAMS, sizeof(RSA_17200_PARAMS) / sizeof(RSA_17200_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = { opensslRsaKeyLen, opensslRsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = { rsaPublicKeyLen, rsaPublicKey };
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = { .size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), RSA_FAILED);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_17300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17300
 * @tc.name      : HksRsaEcbOaepSha384Mt17300
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17300_PARAMS, sizeof(RSA_17300_PARAMS) / sizeof(RSA_17300_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
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

static const struct HksParam RSA_17400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17400
 * @tc.name      : HksRsaEcbOaepSha384Mt17400
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17400_PARAMS, sizeof(RSA_17400_PARAMS) / sizeof(RSA_17400_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = { opensslRsaKeyLen, opensslRsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = { rsaPublicKeyLen, rsaPublicKey };
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = { .size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);
    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_17500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17500
 * @tc.name      : HksRsaEcbOaepSha384Mt17500
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17500_PARAMS, sizeof(RSA_17500_PARAMS) / sizeof(RSA_17500_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
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

static const struct HksParam RSA_17600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17600
 * @tc.name      : HksRsaEcbOaepSha384Mt17600
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17600_PARAMS, sizeof(RSA_17600_PARAMS) / sizeof(RSA_17600_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = { opensslRsaKeyLen, opensslRsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = { rsaPublicKeyLen, rsaPublicKey };
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = { .size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);
    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_17700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17700
 * @tc.name      : HksRsaEcbOaepSha384Mt17700
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17700_PARAMS, sizeof(RSA_17700_PARAMS) / sizeof(RSA_17700_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
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

static const struct HksParam RSA_17800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17800
 * @tc.name      : HksRsaEcbOaepSha384Mt17800
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17800_PARAMS, sizeof(RSA_17800_PARAMS) / sizeof(RSA_17800_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = { opensslRsaKeyLen, opensslRsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = { rsaPublicKeyLen, rsaPublicKey };
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = { .size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);
    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_17900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt17900
 * @tc.name      : HksRsaEcbOaepSha384Mt17900
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt17900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_17900_PARAMS, sizeof(RSA_17900_PARAMS) / sizeof(RSA_17900_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *pubKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyExport), HKS_SUCCESS);

    HksBlob publicKey = { .size = pubKeyExport->blob.size, .data = (uint8_t *)malloc(pubKeyExport->blob.size) };
    ASSERT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, pubKeyExport->blob.size, pubKeyExport->blob.data, pubKeyExport->blob.size);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
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

static const struct HksParam RSA_18000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaEcbOaepSha384Mt18000
 * @tc.name      : HksRsaEcbOaepSha384Mt18000
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/OAEPWithSHA-384AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha384Mt, HksRsaEcbOaepSha384Mt18000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_18000_PARAMS, sizeof(RSA_18000_PARAMS) / sizeof(RSA_18000_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);
    uint8_t opensslRsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslRsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslRsaKeyInfo = { opensslRsaKeyLen, opensslRsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslRsaKeyInfo), HKS_SUCCESS);

    uint8_t rsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t rsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob rsaPublicKeyInfo = { rsaPublicKeyLen, rsaPublicKey };
    EXPECT_EQ(X509ToRsaPublicKey(&opensslRsaKeyInfo, &rsaPublicKeyInfo), 0);
    HksBlob publicKey = { .size = rsaPublicKeyInfo.size, .data = (uint8_t *)malloc(rsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, rsaPublicKeyInfo.data, rsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA384), 0);
    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
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