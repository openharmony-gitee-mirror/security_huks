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

#include <gtest/gtest.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_openssl_rsa_test_mt.h"
#include "hks_param.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

using namespace testing::ext;
namespace {
namespace {
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for OAEPPadding";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
}  // namespace

class HksRsaEcbOaepPaddingMt : public testing::Test {};

static const struct HksParam RSA_03100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest03100
 * @tc.name      : HksRsaMtTest03100
 * @tc.desc      : Test huks generate key (512_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest03100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03100_PARAMS, sizeof(RSA_03100_PARAMS) / sizeof(RSA_03100_PARAMS[0])),
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

static const struct HksParam RSA_03200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest03200
 * @tc.name      : HksRsaMtTest03200
 * @tc.desc      : Test huks generate key (768_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest03200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03200_PARAMS, sizeof(RSA_03200_PARAMS) / sizeof(RSA_03200_PARAMS[0])),
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

static const struct HksParam RSA_03300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest03300
 * @tc.name      : HksRsaMtTest03300
 * @tc.desc      : Test huks generate key (1024_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest03300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03300_PARAMS, sizeof(RSA_03300_PARAMS) / sizeof(RSA_03300_PARAMS[0])),
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

static const struct HksParam RSA_03400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};
/**
 * @tc.number    : HksRsaMtTest03400
 * @tc.name      : HksRsaMtTest03400
 * @tc.desc      : Test huks generate key (2048_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest03400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03400_PARAMS, sizeof(RSA_03400_PARAMS) / sizeof(RSA_03400_PARAMS[0])),
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

static const struct HksParam RSA_03500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest03500
 * @tc.name      : HksRsaMtTest03500
 * @tc.desc      : Test huks generate key (3072_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest03500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03500_PARAMS, sizeof(RSA_03500_PARAMS) / sizeof(RSA_03500_PARAMS[0])),
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

static const struct HksParam RSA_03600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest03600
 * @tc.name      : HksRsaMtTest03600
 * @tc.desc      : Test huks generate key (4096_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest03600, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03600_PARAMS, sizeof(RSA_03600_PARAMS) / sizeof(RSA_03600_PARAMS[0])),
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

static const struct HksParam RSA_03700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest03700
 * @tc.name      : HksRsaMtTest03700
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest03700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03700_PARAMS, sizeof(RSA_03700_PARAMS) / sizeof(RSA_03700_PARAMS[0])),
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

static const struct HksParam RSA_03800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest03800
 * @tc.name      : HksRsaMtTest03800
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest03800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03800_PARAMS, sizeof(RSA_03800_PARAMS) / sizeof(RSA_03800_PARAMS[0])),
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

static const struct HksParam RSA_03900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest03900
 * @tc.name      : HksRsaMtTest03900
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest03900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03900_PARAMS, sizeof(RSA_03900_PARAMS) / sizeof(RSA_03900_PARAMS[0])),
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

static const struct HksParam RSA_04000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04000
 * @tc.name      : HksRsaMtTest04000
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04000_PARAMS, sizeof(RSA_04000_PARAMS) / sizeof(RSA_04000_PARAMS[0])),
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

static const struct HksParam RSA_04100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04100
 * @tc.name      : HksRsaMtTest04100
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04100_PARAMS, sizeof(RSA_04100_PARAMS) / sizeof(RSA_04100_PARAMS[0])),
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

static const struct HksParam RSA_04200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04200
 * @tc.name      : HksRsaMtTest04200
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04200_PARAMS, sizeof(RSA_04200_PARAMS) / sizeof(RSA_04200_PARAMS[0])),
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

static const struct HksParam RSA_04300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04300
 * @tc.name      : HksRsaMtTest04300
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04300_PARAMS, sizeof(RSA_04300_PARAMS) / sizeof(RSA_04300_PARAMS[0])),
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

static const struct HksParam RSA_04400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04400
 * @tc.name      : HksRsaMtTest04400
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04400_PARAMS, sizeof(RSA_04400_PARAMS) / sizeof(RSA_04400_PARAMS[0])),
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

static const struct HksParam RSA_04500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04500
 * @tc.name      : HksRsaMtTest04500
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04500_PARAMS, sizeof(RSA_04500_PARAMS) / sizeof(RSA_04500_PARAMS[0])),
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

static const struct HksParam RSA_04600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04600
 * @tc.name      : HksRsaMtTest04600
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04600_PARAMS, sizeof(RSA_04600_PARAMS) / sizeof(RSA_04600_PARAMS[0])),
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

static const struct HksParam RSA_04700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04700
 * @tc.name      : HksRsaMtTest04700
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04700_PARAMS, sizeof(RSA_04700_PARAMS) / sizeof(RSA_04700_PARAMS[0])),
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

static const struct HksParam RSA_04800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04800
 * @tc.name      : HksRsaMtTest04800
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04800_PARAMS, sizeof(RSA_04800_PARAMS) / sizeof(RSA_04800_PARAMS[0])),
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

static const struct HksParam RSA_04900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest04900
 * @tc.name      : HksRsaMtTest04900
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest04900, TestSize.Level1)

{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_04900_PARAMS, sizeof(RSA_04900_PARAMS) / sizeof(RSA_04900_PARAMS[0])),
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

static const struct HksParam RSA_05000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05000
 * @tc.name      : HksRsaMtTest05000
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05000_PARAMS, sizeof(RSA_05000_PARAMS) / sizeof(RSA_05000_PARAMS[0])),
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

static const struct HksParam RSA_05100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05100
 * @tc.name      : HksRsaMtTest05100
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05100_PARAMS, sizeof(RSA_05100_PARAMS) / sizeof(RSA_05100_PARAMS[0])),
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

static const struct HksParam RSA_05200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05200
 * @tc.name      : HksRsaMtTest05200
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05200_PARAMS, sizeof(RSA_05200_PARAMS) / sizeof(RSA_05200_PARAMS[0])),
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

static const struct HksParam RSA_05300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05300
 * @tc.name      : HksRsaMtTest05300
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05300_PARAMS, sizeof(RSA_05300_PARAMS) / sizeof(RSA_05300_PARAMS[0])),
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

static const struct HksParam RSA_05400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05400
 * @tc.name      : HksRsaMtTest05400
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05400_PARAMS, sizeof(RSA_05400_PARAMS) / sizeof(RSA_05400_PARAMS[0])),
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

static const struct HksParam RSA_05500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05500
 * @tc.name      : HksRsaMtTest05500
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05500_PARAMS, sizeof(RSA_05500_PARAMS) / sizeof(RSA_05500_PARAMS[0])),
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

static const struct HksParam RSA_05600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05600
 * @tc.name      : HksRsaMtTest05600
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05600_PARAMS, sizeof(RSA_05600_PARAMS) / sizeof(RSA_05600_PARAMS[0])),
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

static const struct HksParam RSA_05700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05700
 * @tc.name      : HksRsaMtTest05700
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05700_PARAMS, sizeof(RSA_05700_PARAMS) / sizeof(RSA_05700_PARAMS[0])),
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

static const struct HksParam RSA_05800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05800
 * @tc.name      : HksRsaMtTest05800
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05800_PARAMS, sizeof(RSA_05800_PARAMS) / sizeof(RSA_05800_PARAMS[0])),
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

static const struct HksParam RSA_05900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest05900
 * @tc.name      : HksRsaMtTest05900
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/RSA/ECB/OAEPPadding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest05900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_05900_PARAMS, sizeof(RSA_05900_PARAMS) / sizeof(RSA_05900_PARAMS[0])),
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

static const struct HksParam RSA_06000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest06000
 * @tc.name      : HksRsaMtTest06000
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/RSA/ECB/OAEPPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepPaddingMt, HksRsaMtTest06000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_06000_PARAMS, sizeof(RSA_06000_PARAMS) / sizeof(RSA_06000_PARAMS[0])),
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