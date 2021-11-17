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
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for Sha256AndPss";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
}  // namespace

class HksRsaSha256WithRsaPssMt : public testing::Test {};

static const struct HksParam RSA_40900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest40900
 * @tc.name      : HksRsaMtTest40900
 * @tc.desc      : Test huks sign (512/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest40900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_40900_PARAMS, sizeof(RSA_40900_PARAMS) / sizeof(RSA_40900_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41000
 * @tc.name      : HksRsaMtTest41000
 * @tc.desc      : Test huks sign (512/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41000_PARAMS, sizeof(RSA_41000_PARAMS) / sizeof(RSA_41000_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41100
 * @tc.name      : HksRsaMtTest41100
 * @tc.desc      : Test huks Verify (512/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41100_PARAMS, sizeof(RSA_41100_PARAMS) / sizeof(RSA_41100_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41200
 * @tc.name      : HksRsaMtTest41200
 * @tc.desc      : Test huks Verify (512/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41200_PARAMS, sizeof(RSA_41200_PARAMS) / sizeof(RSA_41200_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41300
 * @tc.name      : HksRsaMtTest41300
 * @tc.desc      : Test huks sign (768/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41300_PARAMS, sizeof(RSA_41300_PARAMS) / sizeof(RSA_41300_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41400
 * @tc.name      : HksRsaMtTest41400
 * @tc.desc      : Test huks sign (768/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41400_PARAMS, sizeof(RSA_41400_PARAMS) / sizeof(RSA_41400_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41500
 * @tc.name      : HksRsaMtTest41500
 * @tc.desc      : Test huks Verify (768/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41500_PARAMS, sizeof(RSA_41500_PARAMS) / sizeof(RSA_41500_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41600
 * @tc.name      : HksRsaMtTest41600
 * @tc.desc      : Test huks Verify (768/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41600_PARAMS, sizeof(RSA_41600_PARAMS) / sizeof(RSA_41600_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41700
 * @tc.name      : HksRsaMtTest41700
 * @tc.desc      : Test huks sign (1024/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41700_PARAMS, sizeof(RSA_41700_PARAMS) / sizeof(RSA_41700_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41800
 * @tc.name      : HksRsaMtTest41800
 * @tc.desc      : Test huks sign (1024/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41800_PARAMS, sizeof(RSA_41800_PARAMS) / sizeof(RSA_41800_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_41900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest41900
 * @tc.name      : HksRsaMtTest41900
 * @tc.desc      : Test huks Verify (1024/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest41900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_41900_PARAMS, sizeof(RSA_41900_PARAMS) / sizeof(RSA_41900_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42000
 * @tc.name      : HksRsaMtTest42000
 * @tc.desc      : Test huks Verify (1024/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42000_PARAMS, sizeof(RSA_42000_PARAMS) / sizeof(RSA_42000_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42100
 * @tc.name      : HksRsaMtTest42100
 * @tc.desc      : Test huks sign (2048/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42100_PARAMS, sizeof(RSA_42100_PARAMS) / sizeof(RSA_42100_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42200
 * @tc.name      : HksRsaMtTest42200
 * @tc.desc      : Test huks sign (2048/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42200_PARAMS, sizeof(RSA_42200_PARAMS) / sizeof(RSA_42200_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42300
 * @tc.name      : HksRsaMtTest42300
 * @tc.desc      : Test huks Verify (2048/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42300_PARAMS, sizeof(RSA_42300_PARAMS) / sizeof(RSA_42300_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42400
 * @tc.name      : HksRsaMtTest42400
 * @tc.desc      : Test huks Verify (2048/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42400_PARAMS, sizeof(RSA_42400_PARAMS) / sizeof(RSA_42400_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42500
 * @tc.name      : HksRsaMtTest42500
 * @tc.desc      : Test huks sign (3072/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42500_PARAMS, sizeof(RSA_42500_PARAMS) / sizeof(RSA_42500_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42600
 * @tc.name      : HksRsaMtTest42600
 * @tc.desc      : Test huks sign (3072/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42600_PARAMS, sizeof(RSA_42600_PARAMS) / sizeof(RSA_42600_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42700
 * @tc.name      : HksRsaMtTest42700
 * @tc.desc      : Test huks Verify (3072/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42700_PARAMS, sizeof(RSA_42700_PARAMS) / sizeof(RSA_42700_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42800
 * @tc.name      : HksRsaMtTest42800
 * @tc.desc      : Test huks Verify (3072/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42800_PARAMS, sizeof(RSA_42800_PARAMS) / sizeof(RSA_42800_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_42900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest42900
 * @tc.name      : HksRsaMtTest42900
 * @tc.desc      : Test huks sign (4096/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest42900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_42900_PARAMS, sizeof(RSA_42900_PARAMS) / sizeof(RSA_42900_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_43000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest43000
 * @tc.name      : HksRsaMtTest43000
 * @tc.desc      : Test huks sign (4096/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest43000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_43000_PARAMS, sizeof(RSA_43000_PARAMS) / sizeof(RSA_43000_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_43100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest43100
 * @tc.name      : HksRsaMtTest43100
 * @tc.desc      : Test huks Verify (4096/SHA256withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest43100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_43100_PARAMS, sizeof(RSA_43100_PARAMS) / sizeof(RSA_43100_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_43200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest43200
 * @tc.name      : HksRsaMtTest43200
 * @tc.desc      : Test huks Verify (4096/SHA256withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha256WithRsaPssMt, HksRsaMtTest43200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_43200_PARAMS, sizeof(RSA_43200_PARAMS) / sizeof(RSA_43200_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace