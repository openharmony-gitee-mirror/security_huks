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
namespace {
const char TEST_AES_128KEY[] = "This is a AES_128 key";
const char TEST_AES_192KEY[] = "This is a AES_192 key";
const char TEST_AES_256KEY[] = "This is a AES_256 key";
}  // namespace
class HksAesKeyMtTest : public testing::Test {};

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest00100
 * @tc.name      : HksAesKeyMtTest00100
 * @tc.desc      : Huks generates aes128 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest00100, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest00200
 * @tc.name      : HksAesKeyMtTest00200
 * @tc.desc      : Huks generates aes128 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest00200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest00300
 * @tc.name      : HksAesKeyMtTest00300
 * @tc.desc      : Huks generates aes128 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest00300, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest00400
 * @tc.name      : HksAesKeyMtTest00400
 * @tc.desc      : Huks generates aes128 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest00400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest00500
 * @tc.name      : HksAesKeyMtTest00500
 * @tc.desc      : Huks generates aes128 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest00500, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest00600
 * @tc.name      : HksAesKeyMtTest00600
 * @tc.desc      : Huks generates aes128 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest00600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_128KEY), (uint8_t *)TEST_AES_128KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    uint8_t iv[IV_SIZE] = {0};
    uint8_t aadData[AAD_SIZE] = {0};
    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM},
        {.tag = HKS_TAG_NONCE, .blob = {.size = IV_SIZE, .data = iv}},
        {.tag = HKS_TAG_ASSOCIATED_DATA, .blob = {.size = sizeof(aadData), .data = aadData}},
    };

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    HksBlob tagAead = {.size = 16, .data = (uint8_t *)HksMalloc(16)};
    EXPECT_EQ(AesGCMEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey, &tagAead), AES_SUCCESS);
    EXPECT_EQ(AesGCMDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey, &tagAead), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest00700
 * @tc.name      : HksAesKeyMtTest00700
 * @tc.desc      : Huks generates aes192 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest00700, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest00800
 * @tc.name      : HksAesKeyMtTest00800
 * @tc.desc      : Huks generates aes192 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest00800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest00900
 * @tc.name      : HksAesKeyMtTest00900
 * @tc.desc      : Huks generates aes192 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest00900, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest01000
 * @tc.name      : HksAesKeyMtTest01000
 * @tc.desc      : Huks generates aes192 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest01000, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest01100
 * @tc.name      : HksAesKeyMtTest01100
 * @tc.desc      : Huks generates aes192 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest01100, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest01200
 * @tc.name      : HksAesKeyMtTest01200
 * @tc.desc      : Huks generates aes192 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest01200, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_192KEY), (uint8_t *)TEST_AES_192KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    uint8_t iv[IV_SIZE] = {0};
    uint8_t aadData[AAD_SIZE] = {0};
    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM},
        {.tag = HKS_TAG_NONCE, .blob = {.size = IV_SIZE, .data = iv}},
        {.tag = HKS_TAG_ASSOCIATED_DATA, .blob = {.size = sizeof(aadData), .data = aadData}},
    };

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    HksBlob tagAead = {.size = 16, .data = (uint8_t *)HksMalloc(16)};
    EXPECT_EQ(AesGCMEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey, &tagAead), AES_SUCCESS);
    EXPECT_EQ(AesGCMDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey, &tagAead), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest01300
 * @tc.name      : HksAesKeyMtTest01300
 * @tc.desc      : Huks generates aes256 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest01300, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest01400
 * @tc.name      : HksAesKeyMtTest01400
 * @tc.desc      : Huks generates aes256 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest01400, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest01500
 * @tc.name      : HksAesKeyMtTest01500
 * @tc.desc      : Huks generates aes256 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest01500, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest01600
 * @tc.name      : HksAesKeyMtTest01600
 * @tc.desc      : Huks generates aes256 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest01600, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest01700
 * @tc.name      : HksAesKeyMtTest01700
 * @tc.desc      : Huks generates aes256 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest01700, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };

    uint8_t iv[IV_SIZE] = {0};
    struct HksParam tagIv = {.tag = HKS_TAG_IV, .blob = {.size = IV_SIZE, .data = iv}};
    HksAddParams(paramInSet, &tagIv, 1);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    EXPECT_EQ(AesEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey), AES_SUCCESS);
    EXPECT_EQ(AesDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.number    : HksAesKeyMtTest.HksAesKeyMtTest01800
 * @tc.name      : HksAesKeyMtTest01800
 * @tc.desc      : Huks generates aes256 bit key, which can be successfully used for OpenSSL encryption/decryption using
 * AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesKeyMtTest, HksAesKeyMtTest01800, TestSize.Level1)
{
    struct HksBlob authId = {strlen(TEST_AES_256KEY), (uint8_t *)TEST_AES_256KEY};

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);

    uint8_t iv[IV_SIZE] = {0};
    uint8_t aadData[AAD_SIZE] = {0};
    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM},
        {.tag = HKS_TAG_NONCE, .blob = {.size = IV_SIZE, .data = iv}},
        {.tag = HKS_TAG_ASSOCIATED_DATA, .blob = {.size = sizeof(aadData), .data = aadData}},
    };

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(OUT_PARAMSET_SIZE);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, OUT_PARAMSET_SIZE, 0, OUT_PARAMSET_SIZE);
    paramSetOut->paramSetSize = OUT_PARAMSET_SIZE;

    HksAddParams(paramInSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    HksBuildParamSet(&paramInSet);
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *symmetricParam = NULL;
    HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &symmetricParam);
    HksBlob symmetricKey = {.size = symmetricParam->blob.size, .data = (uint8_t *)malloc(symmetricParam->blob.size)};
    (void)memcpy_s(symmetricKey.data, symmetricParam->blob.size, symmetricParam->blob.data, symmetricParam->blob.size);

    const char *hexData = "0123456789abcdef";
    uint32_t dataLen = strlen(hexData);
    HksBlob plainText = {.size = dataLen, .data = (uint8_t *)hexData};

    uint32_t inLen = dataLen + COMPLEMENT_LEN;
    HksBlob cipherText = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(cipherText.data, nullptr);
    HksBlob plainTextDecrypt = {.size = inLen, .data = (uint8_t *)malloc(inLen)};
    ASSERT_NE(plainTextDecrypt.data, nullptr);
    HksBlob tagAead = {.size = 16, .data = (uint8_t *)HksMalloc(16)};
    EXPECT_EQ(AesGCMEncrypt(paramInSet, &plainText, &cipherText, &symmetricKey, &tagAead), AES_SUCCESS);
    EXPECT_EQ(AesGCMDecrypt(paramInSet, &cipherText, &plainTextDecrypt, &symmetricKey, &tagAead), AES_SUCCESS);

    EXPECT_EQ(plainTextDecrypt.size, dataLen);
    EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, dataLen), 0);

    free(paramSetOut);
    free(symmetricKey.data);
    free(cipherText.data);
    free(plainTextDecrypt.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace