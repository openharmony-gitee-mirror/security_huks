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
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for NoPadding";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
const char HEXDATA_4096[] =
    "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
    "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
    "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
    "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
    "012345678901234567890123456789012345678901234567890123456789012345678901";
}  // namespace

class HksRsaEcbNopaddingMt : public testing::Test {};

static const struct HksParam RSA_00100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest00100
 * @tc.name      : HksRsaMtTest00100
 * @tc.desc      : Test huks generate key (512_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest00100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_00100_PARAMS, sizeof(RSA_00100_PARAMS) / sizeof(RSA_00100_PARAMS[0])),
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

    const char *hexData = "0123456789012345678901234567890123456789012345678901234567890123";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(paramSetOut);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_00200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest00200
 * @tc.name      : HksRsaMtTest00200
 * @tc.desc      : Test huks generate key (768_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest00200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_00200_PARAMS, sizeof(RSA_00200_PARAMS) / sizeof(RSA_00200_PARAMS[0])),
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

    const char *hexData =
        "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_00300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};
/**
 * @tc.number    : HksRsaMtTest00300
 * @tc.name      : HksRsaMtTest00300
 * @tc.desc      : Test huks generate key (1024_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest00300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_00300_PARAMS, sizeof(RSA_00300_PARAMS) / sizeof(RSA_00300_PARAMS[0])),
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

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "234567890123456789012345678901234567";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_00400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest00400
 * @tc.name      : HksRsaMtTest00400
 * @tc.desc      : Test huks generate key (2048_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest00400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_00400_PARAMS, sizeof(RSA_00400_PARAMS) / sizeof(RSA_00400_PARAMS[0])),
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

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123"
                          "456789012345678901234567890123456789012345678901234567890123456789012345";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_00500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest00500
 * @tc.name      : HksRsaMtTest00500
 * @tc.desc      : Test huks generate key (3072_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest00500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_00500_PARAMS, sizeof(RSA_00500_PARAMS) / sizeof(RSA_00500_PARAMS[0])),
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

    const char *hexData =
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "012345678901234567890123456789012345678901234567890123";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_00600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest00600
 * @tc.name      : HksRsaMtTest00600
 * @tc.desc      : Test huks generate key (4096_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest00600, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_00600_PARAMS, sizeof(RSA_00600_PARAMS) / sizeof(RSA_00600_PARAMS[0])),
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

    const char *hexData =
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "012345678901234567890123456789012345678901234567890123456789012345678901";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);
    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_00700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest00700
 * @tc.name      : HksRsaMtTest00700
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest00700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_00700_PARAMS, sizeof(RSA_00700_PARAMS) / sizeof(RSA_00700_PARAMS[0])),
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

    const char *hexData = "0123456789012345678901234567890123456789012345678901234567890123";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_00800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest00800
 * @tc.name      : HksRsaMtTest00800
 * @tc.desc      : Test huks Encrypt (512_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest00800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_00800_PARAMS, sizeof(RSA_00800_PARAMS) / sizeof(RSA_00800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "0123456789012345678901234567890123456789012345678901234567890123";

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

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_512);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_512, &opensslRsaKeyInfo);

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_00900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest00900
 * @tc.name      : HksRsaMtTest00900
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest00900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_00900_PARAMS, sizeof(RSA_00900_PARAMS) / sizeof(RSA_00900_PARAMS[0])),
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

    const char *hexData =
        "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01000
 * @tc.name      : HksRsaMtTest01000
 * @tc.desc      : Test huks Encrypt (768_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01000_PARAMS, sizeof(RSA_01000_PARAMS) / sizeof(RSA_01000_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData =
        "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";

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

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_768);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_768, &opensslRsaKeyInfo);

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01100
 * @tc.name      : HksRsaMtTest01100
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01100_PARAMS, sizeof(RSA_01100_PARAMS) / sizeof(RSA_01100_PARAMS[0])),
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

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "234567890123456789012345678901234567";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01200
 * @tc.name      : HksRsaMtTest01200
 * @tc.desc      : Test huks Encrypt (1024_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01200_PARAMS, sizeof(RSA_01200_PARAMS) / sizeof(RSA_01200_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "234567890123456789012345678901234567";

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

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01300
 * @tc.name      : HksRsaMtTest01300
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01300_PARAMS, sizeof(RSA_01300_PARAMS) / sizeof(RSA_01300_PARAMS[0])),
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

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123"
                          "456789012345678901234567890123456789012345678901234567890123456789012345";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01400
 * @tc.name      : HksRsaMtTest01400
 * @tc.desc      : Test huks Encrypt (2048_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01400_PARAMS, sizeof(RSA_01400_PARAMS) / sizeof(RSA_01400_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123"
                          "456789012345678901234567890123456789012345678901234567890123456789012345";

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

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), RSA_SUCCESS);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01500
 * @tc.name      : HksRsaMtTest01500
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01500_PARAMS, sizeof(RSA_01500_PARAMS) / sizeof(RSA_01500_PARAMS[0])),
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

    const char *hexData =
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "012345678901234567890123456789012345678901234567890123";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01600
 * @tc.name      : HksRsaMtTest01600
 * @tc.desc      : Test huks Encrypt (3072_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01600_PARAMS, sizeof(RSA_01600_PARAMS) / sizeof(RSA_01600_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData =
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "012345678901234567890123456789012345678901234567890123";

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

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01700
 * @tc.name      : HksRsaMtTest01700
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01700_PARAMS, sizeof(RSA_01700_PARAMS) / sizeof(RSA_01700_PARAMS[0])),
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

    HksBlob plainText = { .size = strlen(HEXDATA_4096), .data = (uint8_t *)HEXDATA_4096 };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(DecryptRSA(&cipherText, &decryptedText, &privateKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&publicKey, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01800
 * @tc.name      : HksRsaMtTest01800
 * @tc.desc      : Test huks Encrypt (4096_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01800_PARAMS, sizeof(RSA_01800_PARAMS) / sizeof(RSA_01800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData =
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "012345678901234567890123456789012345678901234567890123456789012345678901";

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

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);

    EXPECT_EQ(
        DecryptRSA(&cipherText, &decryptedText, &opensslRsaKeyInfo, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);
#endif

    EVP_PKEY_free(pkey);
    free(decryptedText.data);
    free(cipherText.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_01900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest01900
 * @tc.name      : HksRsaMtTest01900
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest01900, TestSize.Level1)

{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_01900_PARAMS, sizeof(RSA_01900_PARAMS) / sizeof(RSA_01900_PARAMS[0])),
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

    const char *hexData = "0123456789012345678901234567890123456789012345678901234567890123";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02000
 * @tc.name      : HksRsaMtTest02000
 * @tc.desc      : Test huks Decrypt (512_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02000_PARAMS, sizeof(RSA_02000_PARAMS) / sizeof(RSA_02000_PARAMS[0])),
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

    const char *hexData = "0123456789012345678901234567890123456789012345678901234567890123";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02100
 * @tc.name      : HksRsaMtTest02100
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02100_PARAMS, sizeof(RSA_02100_PARAMS) / sizeof(RSA_02100_PARAMS[0])),
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

    const char *hexData =
        "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02200
 * @tc.name      : HksRsaMtTest02200
 * @tc.desc      : Test huks Decrypt (768_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02200_PARAMS, sizeof(RSA_02200_PARAMS) / sizeof(RSA_02200_PARAMS[0])),
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

    const char *hexData =
        "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02300
 * @tc.name      : HksRsaMtTest02300
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02300_PARAMS, sizeof(RSA_02300_PARAMS) / sizeof(RSA_02300_PARAMS[0])),
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

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "234567890123456789012345678901234567";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02400
 * @tc.name      : HksRsaMtTest02400
 * @tc.desc      : Test huks Decrypt (1024_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02400_PARAMS, sizeof(RSA_02400_PARAMS) / sizeof(RSA_02400_PARAMS[0])),
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

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "234567890123456789012345678901234567";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02500
 * @tc.name      : HksRsaMtTest02500
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02500_PARAMS, sizeof(RSA_02500_PARAMS) / sizeof(RSA_02500_PARAMS[0])),
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

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123"
                          "456789012345678901234567890123456789012345678901234567890123456789012345";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02600
 * @tc.name      : HksRsaMtTest02600
 * @tc.desc      : Test huks Decrypt (2048_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02600_PARAMS, sizeof(RSA_02600_PARAMS) / sizeof(RSA_02600_PARAMS[0])),
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

    const char *hexData = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                          "23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123"
                          "456789012345678901234567890123456789012345678901234567890123456789012345";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02700
 * @tc.name      : HksRsaMtTest02700
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02700_PARAMS, sizeof(RSA_02700_PARAMS) / sizeof(RSA_02700_PARAMS[0])),
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

    const char *hexData =
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "012345678901234567890123456789012345678901234567890123";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02800
 * @tc.name      : HksRsaMtTest02800
 * @tc.desc      : Test huks Decrypt (3072_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02800_PARAMS, sizeof(RSA_02800_PARAMS) / sizeof(RSA_02800_PARAMS[0])),
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

    const char *hexData =
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "012345678901234567890123456789012345678901234567890123";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_02900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest02900
 * @tc.name      : HksRsaMtTest02900
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/RSA/ECB/NoPadding/TEMP)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest02900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_02900_PARAMS, sizeof(RSA_02900_PARAMS) / sizeof(RSA_02900_PARAMS[0])),
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

    HksBlob plainText = { .size = strlen(HEXDATA_4096), .data = (uint8_t *)HEXDATA_4096 };

    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);

    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&privateKey, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_03000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest03000
 * @tc.name      : HksRsaMtTest03000
 * @tc.desc      : Test huks Decrypt (4096_RSA/ECB/RSA/ECB/NoPadding/PERSISTENT)
 */
HWTEST_F(HksRsaEcbNopaddingMt, HksRsaMtTest03000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_03000_PARAMS, sizeof(RSA_03000_PARAMS) / sizeof(RSA_03000_PARAMS[0])),
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

    HksBlob plainText = { .size = strlen(HEXDATA_4096), .data = (uint8_t *)HEXDATA_4096 };
    HksParam *cipherLenBit = NULL;
    HksGetParam(paramInSet, HKS_TAG_KEY_SIZE, &cipherLenBit);
    uint32_t inLength = (cipherLenBit->uint32Param) / BIT_NUM_OF_UINT8;
    HksBlob cipherText = { .size = inLength, .data = (uint8_t *)malloc(inLength) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob decryptedText = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(decryptedText.data, nullptr);

    EXPECT_EQ(EncryptRSA(&plainText, &cipherText, &publicKey, RSA_NO_PADDING, HKS_DIGEST_NONE), RSA_SUCCESS);

#if defined(_USE_OPENSSL_)

    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_SUCCESS);

    EXPECT_EQ((memcmp(plainText.data, decryptedText.data, decryptedText.size)), 0);
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &decryptedText), HKS_ERROR_NOT_SUPPORTED);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(cipherText.data);
    free(decryptedText.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace