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
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for OAEPWithSHA-1";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
}  // namespace

class HksRsaEcbOaepSha1Mt : public testing::Test {};

static const struct HksParam RSA_06100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest06100
 * @tc.name      : HksRsaMtTest06100
 * @tc.desc      : Test huks generate key (512_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest06100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06100_PARAMS, sizeof(RSA_06100_PARAMS) / sizeof(RSA_06100_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(paramSetOut);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_06200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};
/**
 * @tc.number    : HksRsaMtTest06200
 * @tc.name      : HksRsaMtTest06200
 * @tc.desc      : Test huks generate key (768_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest06200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06200_PARAMS, sizeof(RSA_06200_PARAMS) / sizeof(RSA_06200_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_06300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest06300
 * @tc.name      : HksRsaMtTest06300
 * @tc.desc      : Test huks generate key (1024_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest06300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06300_PARAMS, sizeof(RSA_06300_PARAMS) / sizeof(RSA_06300_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_06400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest06400
 * @tc.name      : HksRsaMtTest06400
 * @tc.desc      : Test huks generate key (2048_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest06400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06400_PARAMS, sizeof(RSA_06400_PARAMS) / sizeof(RSA_06400_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_06500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest06500
 * @tc.name      : HksRsaMtTest06500
 * @tc.desc      : Test huks generate key (3072_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest06500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06500_PARAMS, sizeof(RSA_06500_PARAMS) / sizeof(RSA_06500_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_06600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest06600
 * @tc.name      : HksRsaMtTest06600
 * @tc.desc      : Test huks generate key (4096_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest06600, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06600_PARAMS, sizeof(RSA_06600_PARAMS) / sizeof(RSA_06600_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_06700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest06700
 * @tc.name      : HksRsaMtTest06700
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest06700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06700_PARAMS, sizeof(RSA_06700_PARAMS) / sizeof(RSA_06700_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_06800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest06800
 * @tc.name      : HksRsaMtTest06800
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest06800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06800_PARAMS, sizeof(RSA_06800_PARAMS) / sizeof(RSA_06800_PARAMS[0])),
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

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_512);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_512, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_06900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest06900
 * @tc.name      : HksRsaMtTest06900
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest06900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06900_PARAMS, sizeof(RSA_06900_PARAMS) / sizeof(RSA_06900_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07000
 * @tc.name      : HksRsaMtTest07000
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07000_PARAMS, sizeof(RSA_07000_PARAMS) / sizeof(RSA_07000_PARAMS[0])),
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

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_768);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_768, &opensslRsaKeyInfo);

    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07100
 * @tc.name      : HksRsaMtTest07100
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07100_PARAMS, sizeof(RSA_07100_PARAMS) / sizeof(RSA_07100_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07200
 * @tc.name      : HksRsaMtTest07200
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07200_PARAMS, sizeof(RSA_07200_PARAMS) / sizeof(RSA_07200_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07300
 * @tc.name      : HksRsaMtTest07300
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07300_PARAMS, sizeof(RSA_07300_PARAMS) / sizeof(RSA_07300_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07400
 * @tc.name      : HksRsaMtTest07400
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07400_PARAMS, sizeof(RSA_07400_PARAMS) / sizeof(RSA_07400_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07500
 * @tc.name      : HksRsaMtTest07500
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07500_PARAMS, sizeof(RSA_07500_PARAMS) / sizeof(RSA_07500_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07600
 * @tc.name      : HksRsaMtTest07600
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07600_PARAMS, sizeof(RSA_07600_PARAMS) / sizeof(RSA_07600_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07700
 * @tc.name      : HksRsaMtTest07700
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07700_PARAMS, sizeof(RSA_07700_PARAMS) / sizeof(RSA_07700_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07800
 * @tc.name      : HksRsaMtTest07800
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07800_PARAMS, sizeof(RSA_07800_PARAMS) / sizeof(RSA_07800_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_07900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest07900
 * @tc.name      : HksRsaMtTest07900
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest07900, TestSize.Level1)

{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_07900_PARAMS, sizeof(RSA_07900_PARAMS) / sizeof(RSA_07900_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

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

static const struct HksParam RSA_08000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08000
 * @tc.name      : HksRsaMtTest08000
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08000_PARAMS, sizeof(RSA_08000_PARAMS) / sizeof(RSA_08000_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);
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

static const struct HksParam RSA_08100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08100
 * @tc.name      : HksRsaMtTest08100
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08100_PARAMS, sizeof(RSA_08100_PARAMS) / sizeof(RSA_08100_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

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

static const struct HksParam RSA_08200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08200
 * @tc.name      : HksRsaMtTest08200
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08200_PARAMS, sizeof(RSA_08200_PARAMS) / sizeof(RSA_08200_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);
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

static const struct HksParam RSA_08300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08300
 * @tc.name      : HksRsaMtTest08300
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08300_PARAMS, sizeof(RSA_08300_PARAMS) / sizeof(RSA_08300_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

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

static const struct HksParam RSA_08400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08400
 * @tc.name      : HksRsaMtTest08400
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08400_PARAMS, sizeof(RSA_08400_PARAMS) / sizeof(RSA_08400_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);
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

static const struct HksParam RSA_08500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08500
 * @tc.name      : HksRsaMtTest08500
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08500_PARAMS, sizeof(RSA_08500_PARAMS) / sizeof(RSA_08500_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

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

static const struct HksParam RSA_08600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08600
 * @tc.name      : HksRsaMtTest08600
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08600_PARAMS, sizeof(RSA_08600_PARAMS) / sizeof(RSA_08600_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);
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

static const struct HksParam RSA_08700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08700
 * @tc.name      : HksRsaMtTest08700
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08700_PARAMS, sizeof(RSA_08700_PARAMS) / sizeof(RSA_08700_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

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

static const struct HksParam RSA_08800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08800
 * @tc.name      : HksRsaMtTest08800
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08800_PARAMS, sizeof(RSA_08800_PARAMS) / sizeof(RSA_08800_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);
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

static const struct HksParam RSA_08900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest08900
 * @tc.name      : HksRsaMtTest08900
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest08900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_08900_PARAMS, sizeof(RSA_08900_PARAMS) / sizeof(RSA_08900_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);

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

static const struct HksParam RSA_09000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest09000
 * @tc.name      : HksRsaMtTest09000
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/OAEPWithSHA-1AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha1Mt, HksRsaMtTest09000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09000_PARAMS, sizeof(RSA_09000_PARAMS) / sizeof(RSA_09000_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA1), 0);
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