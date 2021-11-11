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
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for NONE";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
}  // namespace

class HksRsaNoneWithRsaMt : public testing::Test {};

static const struct HksParam RSA_26500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest26500
 * @tc.name      : HksRsaMtTest26500
 * @tc.desc      : Test huks sign (512/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest26500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_26500_PARAMS, sizeof(RSA_26500_PARAMS) / sizeof(RSA_26500_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_26600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest26600
 * @tc.name      : HksRsaMtTest26600
 * @tc.desc      : Test huks sign (512/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest26600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_26600_PARAMS, sizeof(RSA_26600_PARAMS) / sizeof(RSA_26600_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_26700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest26700
 * @tc.name      : HksRsaMtTest26700
 * @tc.desc      : Test huks Verify (512/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest26700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_26700_PARAMS, sizeof(RSA_26700_PARAMS) / sizeof(RSA_26700_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_26800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest26800
 * @tc.name      : HksRsaMtTest26800
 * @tc.desc      : Test huks Verify (512/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest26800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_26800_PARAMS, sizeof(RSA_26800_PARAMS) / sizeof(RSA_26800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_512);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_512, &opensslRsaKeyInfo);
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_26900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest26900
 * @tc.name      : HksRsaMtTest26900
 * @tc.desc      : Test huks sign (768/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest26900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_26900_PARAMS, sizeof(RSA_26900_PARAMS) / sizeof(RSA_26900_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27000
 * @tc.name      : HksRsaMtTest27000
 * @tc.desc      : Test huks sign (768/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27000_PARAMS, sizeof(RSA_27000_PARAMS) / sizeof(RSA_27000_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27100
 * @tc.name      : HksRsaMtTest27100
 * @tc.desc      : Test huks Verify (768/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27100_PARAMS, sizeof(RSA_27100_PARAMS) / sizeof(RSA_27100_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27200
 * @tc.name      : HksRsaMtTest27200
 * @tc.desc      : Test huks Verify (768/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27200_PARAMS, sizeof(RSA_27200_PARAMS) / sizeof(RSA_27200_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_768);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_768, &opensslRsaKeyInfo);
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27300
 * @tc.name      : HksRsaMtTest27300
 * @tc.desc      : Test huks sign (1024/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27300_PARAMS, sizeof(RSA_27300_PARAMS) / sizeof(RSA_27300_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27400
 * @tc.name      : HksRsaMtTest27400
 * @tc.desc      : Test huks sign (1024/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27400_PARAMS, sizeof(RSA_27400_PARAMS) / sizeof(RSA_27400_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27500
 * @tc.name      : HksRsaMtTest27500
 * @tc.desc      : Test huks Verify (1024/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27500_PARAMS, sizeof(RSA_27500_PARAMS) / sizeof(RSA_27500_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27600
 * @tc.name      : HksRsaMtTest27600
 * @tc.desc      : Test huks Verify (1024/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27600_PARAMS, sizeof(RSA_27600_PARAMS) / sizeof(RSA_27600_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_1024);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_1024, &opensslRsaKeyInfo);
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27700
 * @tc.name      : HksRsaMtTest27700
 * @tc.desc      : Test huks sign (2048/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27700_PARAMS, sizeof(RSA_27700_PARAMS) / sizeof(RSA_27700_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27800
 * @tc.name      : HksRsaMtTest27800
 * @tc.desc      : Test huks sign (2048/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27800_PARAMS, sizeof(RSA_27800_PARAMS) / sizeof(RSA_27800_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_27900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest27900
 * @tc.name      : HksRsaMtTest27900
 * @tc.desc      : Test huks Verify (2048/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest27900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_27900_PARAMS, sizeof(RSA_27900_PARAMS) / sizeof(RSA_27900_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_28000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest28000
 * @tc.name      : HksRsaMtTest28000
 * @tc.desc      : Test huks Verify (2048/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest28000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_28000_PARAMS, sizeof(RSA_28000_PARAMS) / sizeof(RSA_28000_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_2048);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_2048, &opensslRsaKeyInfo);
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_28100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest28100
 * @tc.name      : HksRsaMtTest28100
 * @tc.desc      : Test huks sign (3072/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest28100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_28100_PARAMS, sizeof(RSA_28100_PARAMS) / sizeof(RSA_28100_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_28200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest28200
 * @tc.name      : HksRsaMtTest28200
 * @tc.desc      : Test huks sign (3072/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest28200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_28200_PARAMS, sizeof(RSA_28200_PARAMS) / sizeof(RSA_28200_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_28300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest28300
 * @tc.name      : HksRsaMtTest28300
 * @tc.desc      : Test huks Verify (3072/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest28300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_28300_PARAMS, sizeof(RSA_28300_PARAMS) / sizeof(RSA_28300_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_28400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest28400
 * @tc.name      : HksRsaMtTest28400
 * @tc.desc      : Test huks Verify (3072/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest28400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_28400_PARAMS, sizeof(RSA_28400_PARAMS) / sizeof(RSA_28400_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_3072);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_3072, &opensslRsaKeyInfo);
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_28500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest28500
 * @tc.name      : HksRsaMtTest28500
 * @tc.desc      : Test huks sign (4096/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest28500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_28500_PARAMS, sizeof(RSA_28500_PARAMS) / sizeof(RSA_28500_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_28600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest28600
 * @tc.name      : HksRsaMtTest28600
 * @tc.desc      : Test huks sign (4096/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest28600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_28600_PARAMS, sizeof(RSA_28600_PARAMS) / sizeof(RSA_28600_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_28700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest28700
 * @tc.name      : HksRsaMtTest28700
 * @tc.desc      : Test huks Verify (4096/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest28700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_28700_PARAMS, sizeof(RSA_28700_PARAMS) / sizeof(RSA_28700_PARAMS[0])),
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

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_28800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest28800
 * @tc.name      : HksRsaMtTest28800
 * @tc.desc      : Test huks Verify (4096/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaMtTest28800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_28800_PARAMS, sizeof(RSA_28800_PARAMS) / sizeof(RSA_28800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateRSAKey(SET_SIZE_4096);
    ASSERT_NE(pkey, nullptr);

    OpensslGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveRsaKeyToHksBlob(pkey, SET_SIZE_4096, &opensslRsaKeyInfo);
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PADDING, HKS_DIGEST_NONE), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace