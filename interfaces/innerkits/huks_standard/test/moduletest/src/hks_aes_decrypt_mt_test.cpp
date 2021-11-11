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
static const struct HksParam AES_DECRYPT_00500_PARAMS[] = {
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
static const struct HksParam AES_DECRYPT_01100_PARAMS[] = {
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
static const struct HksParam AES_DECRYPT_01700_PARAMS[] = {
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

class HksAesDecryptMtTest : public testing::Test {};

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest00100
 * @tc.name      : HksAesDecryptMtTest00100
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for OpenSSL encryption using
 * AES/CBC/pkcs7padding algorithm and huks decryption using AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest00100, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest00200
 * @tc.name      : HksAesDecryptMtTest00200
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for OpenSSL encryption using
 * AES/CBC/nopadding algorithm and huks decryption using AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest00200, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest00300
 * @tc.name      : HksAesDecryptMtTest00300
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for OpenSSL encryption using
 * AES/CTR/nopadding algorithm and huks decryption using AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest00300, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest00400
 * @tc.name      : HksAesDecryptMtTest00400
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for OpenSSL encryption using
 * AES/ECB/nopadding algorithm and huks decryption using AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest00400, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest00500
 * @tc.name      : HksAesDecryptMtTest00500
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for OpenSSL encryption using
 * AES/ECB/pkcs7padding algorithm and huks decryption using AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest00500, TestSize.Level1)
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
        paramInSet, AES_DECRYPT_00500_PARAMS, sizeof(AES_DECRYPT_00500_PARAMS) / sizeof(AES_DECRYPT_00500_PARAMS[0]));
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
#if defined(_USE_MBEDTLS_)
    ASSERT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_ERROR_NOT_SUPPORTED);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest00600
 * @tc.name      : HksAesDecryptMtTest00600
 * @tc.desc      : OpenSSL generates an aes128 bit key, which can be successfully used for OpenSSL encryption using
 * AES/GCM/nopadding algorithm and huks decryption using AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest00600, TestSize.Level1)
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
    EXPECT_EQ(AesGCMEncrypt(paramInSet, &plainText, &cipherText, &authId, &tagAead), AES_SUCCESS);
    cipherText.size = 32;
    (void)memcpy_s(cipherText.data + 16, 16, tagAead.data, 16);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest00700
 * @tc.name      : HksAesDecryptMtTest00700
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for OpenSSL encryption using
 * AES/CBC/pkcs7padding algorithm and huks decryption using AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest00700, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest00800
 * @tc.name      : HksAesDecryptMtTest00800
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for OpenSSL encryption using
 * AES/CBC/nopadding algorithm and huks decryption using AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest00800, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest00900
 * @tc.name      : HksAesDecryptMtTest00900
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for OpenSSL encryption using
 * AES/CTR/nopadding algorithm and huks decryption using AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest00900, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest01000
 * @tc.name      : HksAesDecryptMtTest01000
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for OpenSSL encryption using
 * AES/ECB/nopadding algorithm and huks decryption using AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest01000, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest01100
 * @tc.name      : HksAesDecryptMtTest01100
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for OpenSSL encryption using
 * AES/ECB/pkcs7padding algorithm and huks decryption using AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest01100, TestSize.Level1)
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
        paramInSet, AES_DECRYPT_01100_PARAMS, sizeof(AES_DECRYPT_01100_PARAMS) / sizeof(AES_DECRYPT_01100_PARAMS[0]));
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
#if defined(_USE_MBEDTLS_)
    ASSERT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_ERROR_NOT_SUPPORTED);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest01200
 * @tc.name      : HksAesDecryptMtTest01200
 * @tc.desc      : OpenSSL generates an aes192 bit key, which can be successfully used for OpenSSL encryption using
 * AES/GCM/nopadding algorithm and huks decryption using AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest01200, TestSize.Level1)
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
    EXPECT_EQ(AesGCMEncrypt(paramInSet, &plainText, &cipherText, &authId, &tagAead), AES_SUCCESS);
    cipherText.size = 32;
    (void)memcpy_s(cipherText.data + 16, 16, tagAead.data, 16);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest01300
 * @tc.name      : HksAesDecryptMtTest01300
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for OpenSSL encryption using
 * AES/CBC/pkcs7padding algorithm and huks decryption using AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest01300, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest01400
 * @tc.name      : HksAesDecryptMtTest01400
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for OpenSSL encryption using
 * AES/CBC/nopadding algorithm and huks decryption using AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest01400, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest01500
 * @tc.name      : HksAesDecryptMtTest01500
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for OpenSSL encryption using
 * AES/CTR/nopadding algorithm and huks decryption using AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest01500, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}
/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest01600
 * @tc.name      : HksAesDecryptMtTest01600
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for OpenSSL encryption using
 * AES/ECB/nopadding algorithm and huks decryption using AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest01600, TestSize.Level1)
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest01700
 * @tc.name      : HksAesDecryptMtTest01700
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for OpenSSL encryption using
 * AES/ECB/pkcs7padding algorithm and huks decryption using AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest01700, TestSize.Level1)
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
        paramInSet, AES_DECRYPT_01700_PARAMS, sizeof(AES_DECRYPT_01700_PARAMS) / sizeof(AES_DECRYPT_01700_PARAMS[0]));
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
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &authId), AES_SUCCESS);
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
#if defined(_USE_MBEDTLS_)
    ASSERT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_ERROR_NOT_SUPPORTED);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
#endif
}

/**
 * @tc.number    : HksAesDecryptMtTest.HksAesDecryptMtTest01800
 * @tc.name      : HksAesDecryptMtTest01800
 * @tc.desc      : OpenSSL generates an aes256 bit key, which can be successfully used for OpenSSL encryption using
 * AES/GCM/nopadding algorithm and huks decryption using AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesDecryptMtTest, HksAesDecryptMtTest01800, TestSize.Level1)
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
    EXPECT_EQ(AesGCMEncrypt(paramInSet, &plainText, &cipherText, &authId, &tagAead), AES_SUCCESS);
    cipherText.size = 32;
    (void)memcpy_s(cipherText.data + 16, 16, tagAead.data, 16);
    EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), HKS_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace