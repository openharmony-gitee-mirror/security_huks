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

using namespace testing::ext;
namespace {
namespace {
const char TEST_AES_128KEY[] = "This is a AES_128 key";
const char TEST_AES_192KEY[] = "This is a AES_192 key";
const char TEST_AES_256KEY[] = "This is a AES_256 key";
static const struct HksParam AES_ENCRYPT_00500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};
static const struct HksParam AES_ENCRYPT_01100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};
static const struct HksParam AES_ENCRYPT_01700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};
}  // namespace
class HksAesEncryptMtTest : public testing::Test {};

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest00100
 * @tc.name      : HksAesEncryptMtTest00100
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for huks encryption using
 * AES/CBC/pkcs7padding algorithm, and OpenSSL decrypts using AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest00100, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_128, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen + COMPLEMENT_LEN;

    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest00200
 * @tc.name      : HksAesEncryptMtTest00200
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for huks encryption using
 * AES/CBC/nopadding algorithm, and OpenSSL decrypts using AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest00200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_128, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest00300
 * @tc.name      : HksAesEncryptMtTest00300
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for huks encryption using
 * AES/CTR/nopadding algorithm, and OpenSSL decrypts using AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest00300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_128, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest00400
 * @tc.name      : HksAesEncryptMtTest00400
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for huks encryption using
 * AES/ECB/nopadding algorithm, and OpenSSL decrypts using AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest00400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_128, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest00500
 * @tc.name      : HksAesEncryptMtTest00500
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for huks encryption using
 * AES/ECB/pkcs7padding algorithm, and OpenSSL decrypts using AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest00500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(
        paramInSet, AES_ENCRYPT_00500_PARAMS, sizeof(AES_ENCRYPT_00500_PARAMS) / sizeof(AES_ENCRYPT_00500_PARAMS[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_128, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
#if defined(_USE_MBEDTLS_)
    ASSERT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest00600
 * @tc.name      : HksAesEncryptMtTest00600
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for huks encryption using
 * AES/GCM/nopadding algorithm, and OpenSSL decrypts using AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest00600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_NONCE, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    uint8_t aadData[AAD_SIZE] = {0};
    struct HksParam aad = { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = sizeof(aadData), .data = aadData } };
    HksAddParams(paramInSet, &aad, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_128, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    (void)memcpy_s(tagAead.data, 16, cipherText.data + 16, 16);
    cipherText.size = 16;
    EXPECT_EQ(AesGCMDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId, &tagAead), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest00700
 * @tc.name      : HksAesEncryptMtTest00700
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for huks encryption using
 * AES/CBC/pkcs7padding algorithm, and OpenSSL decrypts using AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest00700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_192, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest00800
 * @tc.name      : HksAesEncryptMtTest00800
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for huks encryption using
 * AES/CBC/nopadding algorithm, and OpenSSL decrypts using AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest00800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_192, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest00900
 * @tc.name      : HksAesEncryptMtTest00900
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for huks encryption using
 * AES/CTR/nopadding algorithm, and OpenSSL decrypts using AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest00900, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_192, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest01000
 * @tc.name      : HksAesEncryptMtTest01000
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for huks encryption using
 * AES/ECB/nopadding algorithm, and OpenSSL decrypts using AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest01000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_192, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest01100
 * @tc.name      : HksAesEncryptMtTest01100
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for huks encryption using
 * AES/ECB/pkcs7padding algorithm, and OpenSSL decrypts using AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest01100, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(
        paramInSet, AES_ENCRYPT_01100_PARAMS, sizeof(AES_ENCRYPT_01100_PARAMS) / sizeof(AES_ENCRYPT_01100_PARAMS[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_192, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
#if defined(_USE_MBEDTLS_)
    ASSERT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest01200
 * @tc.name      : HksAesEncryptMtTest01200
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for huks encryption using
 * AES/GCM/nopadding algorithm, and OpenSSL decrypts using AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest01200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_NONCE, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    uint8_t aadData[AAD_SIZE] = {0};
    struct HksParam aad = { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = sizeof(aadData), .data = aadData } };
    HksAddParams(paramInSet, &aad, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_192, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    (void)memcpy_s(tagAead.data, 16, cipherText.data + 16, 16);
    cipherText.size = 16;
    EXPECT_EQ(AesGCMDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId, &tagAead), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest01300
 * @tc.name      : HksAesEncryptMtTest01300
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for huks encryption using
 * AES/CBC/pkcs7padding algorithm, and OpenSSL decrypts using AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest01300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_256, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest01400
 * @tc.name      : HksAesEncryptMtTest01400
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for huks encryption using
 * AES/CBC/nopadding algorithm, and OpenSSL decrypts using AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest01400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_256, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest01500
 * @tc.name      : HksAesEncryptMtTest01500
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for huks encryption using
 * AES/CTR/nopadding algorithm, and OpenSSL decrypts using AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest01500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_256, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest01600
 * @tc.name      : HksAesEncryptMtTest01600
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for huks encryption using
 * AES/ECB/nopadding algorithm, and OpenSSL decrypts using AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest01600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_256, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest01700
 * @tc.name      : HksAesEncryptMtTest01700
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for huks encryption using
 * AES/ECB/pkcs7padding algorithm, and OpenSSL decrypts using AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest01700, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(
        paramInSet, AES_ENCRYPT_01700_PARAMS, sizeof(AES_ENCRYPT_01700_PARAMS) / sizeof(AES_ENCRYPT_01700_PARAMS[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_256, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
#if defined(_USE_MBEDTLS_)
    ASSERT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_ERROR_NOT_SUPPORTED);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
}

/**
 * @tc.number    : HksAesEncryptMtTest.HksAesEncryptMtTest01800
 * @tc.name      : HksAesEncryptMtTest01800
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for huks encryption using
 * AES/GCM/nopadding algorithm, and OpenSSL decrypts using AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesEncryptMtTest, HksAesEncryptMtTest01800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = { .tag = HKS_TAG_NONCE, .blob = { .size = IV_SIZE, .data = iv } };
    HksAddParams(paramInSet, &tagIv, 1);

    uint8_t aadData[AAD_SIZE] = {0};
    struct HksParam aad = { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = sizeof(aadData), .data = aadData } };
    HksAddParams(paramInSet, &aad, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    GenerateAesKey(HKS_AES_KEY_SIZE_256, &authId);
    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = { .size = dataLen, .data = (uint8_t *)hexData };

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)malloc(inLen) };
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };
    EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), HKS_SUCCESS);
    (void)memcpy_s(tagAead.data, 16, cipherText.data + 16, 16);
    cipherText.size = 16;
    EXPECT_EQ(AesGCMDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &authId, &tagAead), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace