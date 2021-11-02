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

#include "hks_openssl_aes_test_mt.h"

#include <gtest/gtest.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

using namespace testing::ext;
namespace {
class HksAesCipherMtTest : public testing::Test {};

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest00100
 * @tc.name      : HksAesCipherMtTest00100
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest00100, TestSize.Level1)
{
    uint8_t key[50] = "AES_128_CBC_PKCS7Padding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);
    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest00200
 * @tc.name      : HksAesCipherMtTest00200
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest00200, TestSize.Level1)
{
    uint8_t key[50] = "AES_128_CBC_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest00300
 * @tc.name      : HksAesCipherMtTest00300
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest00300, TestSize.Level1)
{
    uint8_t key[50] = "AES_128_CTR_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest00400
 * @tc.name      : HksAesCipherMtTest00400
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest00400, TestSize.Level1)
{
    uint8_t key[50] = "AES_128_ECB_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest00500
 * @tc.name      : HksAesCipherMtTest00500
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest00500, TestSize.Level1)
{
    uint8_t key[50] = "AES_128_ECB_PKCS7Padding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest00600
 * @tc.name      : HksAesCipherMtTest00600
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest00600, TestSize.Level1)
{
    uint8_t key[50] = "AES_128_GCM_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_NONCE, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    uint8_t aadData[AAD_SIZE] = {0};
    struct HksParam aad = {.tag = HKS_TAG_ASSOCIATED_DATA, .blob = {.size = sizeof(aadData), .data = aadData}};
    HksAddParams(paramInSet, &aad, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest00700
 * @tc.name      : HksAesCipherMtTest00700
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest00700, TestSize.Level1)
{
    uint8_t key[50] = "AES_192_CBC_PKCS7Padding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest00800
 * @tc.name      : HksAesCipherMtTest00800
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest00800, TestSize.Level1)
{
    uint8_t key[50] = "AES_192_CBC_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest00900
 * @tc.name      : HksAesCipherMtTest00900
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest00900, TestSize.Level1)
{
    uint8_t key[50] = "AES_192_CTR_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest01000
 * @tc.name      : HksAesCipherMtTest01000
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest01000, TestSize.Level1)
{
    uint8_t key[50] = "AES_192_ECB_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest01100
 * @tc.name      : HksAesCipherMtTest01100
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest01100, TestSize.Level1)
{
    uint8_t key[50] = "AES_192_ECB_PKCS7Padding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest01200
 * @tc.name      : HksAesCipherMtTest01200
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest01200, TestSize.Level1)
{
    uint8_t key[50] = "AES_192_GCM_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_NONCE, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    uint8_t aadData[AAD_SIZE] = {0};
    struct HksParam aad = {.tag = HKS_TAG_ASSOCIATED_DATA, .blob = {.size = sizeof(aadData), .data = aadData}};
    HksAddParams(paramInSet, &aad, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest01300
 * @tc.name      : HksAesCipherMtTest01300
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest01300, TestSize.Level1)
{
    uint8_t key[50] = "AES_256_CBC_PKCS7Padding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest01400
 * @tc.name      : HksAesCipherMtTest01400
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest01400, TestSize.Level1)
{
    uint8_t key[50] = "AES_256_CBC_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest01500
 * @tc.name      : HksAesCipherMtTest01500
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest01500, TestSize.Level1)
{
    uint8_t key[50] = "AES_256_CTR_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest01600
 * @tc.name      : HksAesCipherMtTest01600
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest01600, TestSize.Level1)
{
    uint8_t key[50] = "AES_256_ECB_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest01700
 * @tc.name      : HksAesCipherMtTest01700
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest01700, TestSize.Level1)
{
    uint8_t key[50] = "AES_256_ECB_PKCS7Padding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesCipherMtTest.HksAesCipherMtTest01800
 * @tc.name      : HksAesCipherMtTest01800
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesCipherMtTest, HksAesCipherMtTest01800, TestSize.Level1)
{
    uint8_t key[50] = "AES_256_GCM_NOPadding";
    struct HksBlob alias = {.size = strlen((char *)key), .data = key};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_NONCE, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    uint8_t aadData[AAD_SIZE] = {0};
    struct HksParam aad = {.tag = HKS_TAG_ASSOCIATED_DATA, .blob = {.size = sizeof(aadData), .data = aadData}};
    HksAddParams(paramInSet, &aad, 1);

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);

    EXPECT_EQ(HksGenerateKey(&alias, paramInSet, NULL), HKS_SUCCESS);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&alias, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(HksDecrypt(&alias, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace