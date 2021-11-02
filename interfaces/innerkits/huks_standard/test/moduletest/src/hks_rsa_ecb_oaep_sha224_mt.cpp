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
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for OAEPWithSHA-224";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
}  // namespace

class HksRsaEcbOaepSha224Mt : public testing::Test {};

static const struct HksParam RSA_09100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};
/**
 * @tc.number    : HksRsaMtTest09100
 * @tc.name      : HksRsaMtTest09100
 * @tc.desc      : Test huks generate key (512_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest09100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09100_PARAMS, sizeof(RSA_09100_PARAMS) / sizeof(RSA_09100_PARAMS[0])),
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

    const char *hexData = "01234";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(paramSetOut);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_09200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest09200
 * @tc.name      : HksRsaMtTest09200
 * @tc.desc      : Test huks generate key (768_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest09200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09200_PARAMS, sizeof(RSA_09200_PARAMS) / sizeof(RSA_09200_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_09300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest09300
 * @tc.name      : HksRsaMtTest09300
 * @tc.desc      : Test huks generate key (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest09300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09300_PARAMS, sizeof(RSA_09300_PARAMS) / sizeof(RSA_09300_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_09400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest09400
 * @tc.name      : HksRsaMtTest09400
 * @tc.desc      : Test huks generate key (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest09400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09400_PARAMS, sizeof(RSA_09400_PARAMS) / sizeof(RSA_09400_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_09500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest09500
 * @tc.name      : HksRsaMtTest09500
 * @tc.desc      : Test huks generate key (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest09500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09500_PARAMS, sizeof(RSA_09500_PARAMS) / sizeof(RSA_09500_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_09600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest09600
 * @tc.name      : HksRsaMtTest09600
 * @tc.desc      : Test huks generate key (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest09600, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09600_PARAMS, sizeof(RSA_09600_PARAMS) / sizeof(RSA_09600_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_09700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest09700
 * @tc.name      : HksRsaMtTest09700
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest09700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09700_PARAMS, sizeof(RSA_09700_PARAMS) / sizeof(RSA_09700_PARAMS[0])),
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

    const char *hexData = "01234";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    HksBlob decryptedText = {.size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096)};
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_09800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest09800
 * @tc.name      : HksRsaMtTest09800
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest09800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09800_PARAMS, sizeof(RSA_09800_PARAMS) / sizeof(RSA_09800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "01234";

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

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_09900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest09900
 * @tc.name      : HksRsaMtTest09900
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest09900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_09900_PARAMS, sizeof(RSA_09900_PARAMS) / sizeof(RSA_09900_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_10000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10000
 * @tc.name      : HksRsaMtTest10000
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10000_PARAMS, sizeof(RSA_10000_PARAMS) / sizeof(RSA_10000_PARAMS[0])),
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

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}
static const struct HksParam RSA_10100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10100
 * @tc.name      : HksRsaMtTest10100
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10100_PARAMS, sizeof(RSA_10100_PARAMS) / sizeof(RSA_10100_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_10200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10200
 * @tc.name      : HksRsaMtTest10200
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10200_PARAMS, sizeof(RSA_10200_PARAMS) / sizeof(RSA_10200_PARAMS[0])),
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
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_10300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10300
 * @tc.name      : HksRsaMtTest10300
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10300_PARAMS, sizeof(RSA_10300_PARAMS) / sizeof(RSA_10300_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_10400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10400
 * @tc.name      : HksRsaMtTest10400
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10400_PARAMS, sizeof(RSA_10400_PARAMS) / sizeof(RSA_10400_PARAMS[0])),
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
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_10500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10500
 * @tc.name      : HksRsaMtTest10500
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10500_PARAMS, sizeof(RSA_10500_PARAMS) / sizeof(RSA_10500_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_10600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10600
 * @tc.name      : HksRsaMtTest10600
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10600_PARAMS, sizeof(RSA_10600_PARAMS) / sizeof(RSA_10600_PARAMS[0])),
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
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_10700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10700
 * @tc.name      : HksRsaMtTest10700
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10700_PARAMS, sizeof(RSA_10700_PARAMS) / sizeof(RSA_10700_PARAMS[0])),
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

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_10800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10800
 * @tc.name      : HksRsaMtTest10800
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10800_PARAMS, sizeof(RSA_10800_PARAMS) / sizeof(RSA_10800_PARAMS[0])),
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
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}
static const struct HksParam RSA_10900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest10900
 * @tc.name      : HksRsaMtTest10900
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest10900, TestSize.Level1)

{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_10900_PARAMS, sizeof(RSA_10900_PARAMS) / sizeof(RSA_10900_PARAMS[0])),
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

    const char *hexData = "012345";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

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

static const struct HksParam RSA_11000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11000
 * @tc.name      : HksRsaMtTest11000
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11000_PARAMS, sizeof(RSA_11000_PARAMS) / sizeof(RSA_11000_PARAMS[0])),
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

    const char *hexData = "01234";

    HksBlob plainText = {.size = strlen(hexData), .data = (uint8_t *)hexData};
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = {.size = inLength, .data = (uint8_t *)malloc(inLength)};
    ASSERT_NE(cipherText.data, nullptr);
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);
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

static const struct HksParam RSA_11100_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11100
 * @tc.name      : HksRsaMtTest11100
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11100_PARAMS, sizeof(RSA_11100_PARAMS) / sizeof(RSA_11100_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

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

static const struct HksParam RSA_11200_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11200
 * @tc.name      : HksRsaMtTest11200
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11200_PARAMS, sizeof(RSA_11200_PARAMS) / sizeof(RSA_11200_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);
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

static const struct HksParam RSA_11300_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11300
 * @tc.name      : HksRsaMtTest11300
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11300_PARAMS, sizeof(RSA_11300_PARAMS) / sizeof(RSA_11300_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

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

static const struct HksParam RSA_11400_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11400
 * @tc.name      : HksRsaMtTest11400
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11400_PARAMS, sizeof(RSA_11400_PARAMS) / sizeof(RSA_11400_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);
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

static const struct HksParam RSA_11500_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11500
 * @tc.name      : HksRsaMtTest11500
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11500_PARAMS, sizeof(RSA_11500_PARAMS) / sizeof(RSA_11500_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

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

static const struct HksParam RSA_11600_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11600
 * @tc.name      : HksRsaMtTest11600
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11600_PARAMS, sizeof(RSA_11600_PARAMS) / sizeof(RSA_11600_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);
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

static const struct HksParam RSA_11700_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11700
 * @tc.name      : HksRsaMtTest11700
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11700_PARAMS, sizeof(RSA_11700_PARAMS) / sizeof(RSA_11700_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

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

static const struct HksParam RSA_11800_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11800
 * @tc.name      : HksRsaMtTest11800
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11800_PARAMS, sizeof(RSA_11800_PARAMS) / sizeof(RSA_11800_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);
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

static const struct HksParam RSA_11900_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest11900
 * @tc.name      : HksRsaMtTest11900
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/TEMP)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest11900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_11900_PARAMS, sizeof(RSA_11900_PARAMS) / sizeof(RSA_11900_PARAMS[0])),
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

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);

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

static const struct HksParam RSA_12000_PARAMS[] = {
    {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
    {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
    {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224},
    {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
    {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
    {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
    {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
};

/**
 * @tc.number    : HksRsaMtTest12000
 * @tc.name      : HksRsaMtTest12000
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/RSA/ECB/OAEPWithSHA-224AndMGF1Padding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbOaepSha224Mt, HksRsaMtTest12000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID};
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_12000_PARAMS, sizeof(RSA_12000_PARAMS) / sizeof(RSA_12000_PARAMS[0])),
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
    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_PKCS1_OAEP_PADDING, HKS_DIGEST_SHA224), 0);
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