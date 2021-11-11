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

#include "hks_openssl_dsa_sign_test_mt.h"

#include <gtest/gtest.h>

#include "hks_api.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace {
namespace {
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for DSA";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_1024 = 1024;
}  // namespace

class HksDsaTestMT : public testing::Test {};

static const struct HksParam DSA_00100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest00100
 * @tc.name      : HksDsaMtTest00100
 * @tc.desc      : Test huks generate key (1024/SHA1withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest00100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_00100_PARAMS, sizeof(DSA_00100_PARAMS) / sizeof(DSA_00100_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA1), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif

    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_00200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest00200
 * @tc.name      : HksDsaMtTest00200
 * @tc.desc      : Test huks sign (1024/SHA1withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest00200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_00200_PARAMS, sizeof(DSA_00200_PARAMS) / sizeof(DSA_00200_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA1), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_00300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest00300
 * @tc.name      : HksDsaMtTest00300
 * @tc.desc      : Test huks sign (1024/SHA1withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest00300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_00300_PARAMS, sizeof(DSA_00300_PARAMS) / sizeof(DSA_00300_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    uint8_t opensslDsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslDsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslDsaKeyInfo = { opensslDsaKeyLen, opensslDsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslDsaKeyInfo), HKS_SUCCESS);

    uint8_t dsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t dsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob dsaPublicKeyInfo = { dsaPublicKeyLen, dsaPublicKey };
    EXPECT_EQ(X509ToDsaPublicKey(&opensslDsaKeyInfo, &dsaPublicKeyInfo), 0);

    HksBlob publicKey = { .size = dsaPublicKeyInfo.size, .data = (uint8_t *)malloc(dsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, dsaPublicKeyInfo.data, dsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA1), 0);

    free(publicKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_00400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest00400
 * @tc.name      : HksDsaMtTest00400
 * @tc.desc      : Test huks Verify (1024/SHA1withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest00400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_00400_PARAMS, sizeof(DSA_00400_PARAMS) / sizeof(DSA_00400_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA1), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif

    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_00500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest00500
 * @tc.name      : HksDsaMtTest00500
 * @tc.desc      : Test huks Verify (1024/SHA1withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest00500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, DSA_00500_PARAMS, sizeof(DSA_00500_PARAMS) / sizeof(DSA_00500_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslDsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslDsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateDsaKey(KEY_SIZE_1024);
    ASSERT_NE(pkey, nullptr);

    DsaGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveDsaKeyToHksBlob(pkey, KEY_SIZE_1024, &opensslDsaKeyInfo);

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &opensslDsaKeyInfo, HKS_DIGEST_SHA1), 0);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_ERROR_INVALID_ARGUMENT);
#else
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);
#endif

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslDsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_00600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest00600
 * @tc.name      : HksDsaMtTest00600
 * @tc.desc      : Test huks generate key (1024/SHA224withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest00600, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_00600_PARAMS, sizeof(DSA_00600_PARAMS) / sizeof(DSA_00600_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA224), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_00700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest00700
 * @tc.name      : HksDsaMtTest00700
 * @tc.desc      : Test huks sign (1024/SHA224withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest00700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_00700_PARAMS, sizeof(DSA_00700_PARAMS) / sizeof(DSA_00700_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA224), 0);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif

    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_00800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest00800
 * @tc.name      : HksDsaMtTest00800
 * @tc.desc      : Test huks sign (1024/SHA224withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest00800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_00800_PARAMS, sizeof(DSA_00800_PARAMS) / sizeof(DSA_00800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    uint8_t opensslDsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslDsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslDsaKeyInfo = { opensslDsaKeyLen, opensslDsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslDsaKeyInfo), HKS_SUCCESS);

    uint8_t dsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t dsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob dsaPublicKeyInfo = { dsaPublicKeyLen, dsaPublicKey };
    EXPECT_EQ(X509ToDsaPublicKey(&opensslDsaKeyInfo, &dsaPublicKeyInfo), 0);

    HksBlob publicKey = { .size = dsaPublicKeyInfo.size, .data = (uint8_t *)malloc(dsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, dsaPublicKeyInfo.data, dsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA224), 0);

    free(publicKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_00900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest00900
 * @tc.name      : HksDsaMtTest00900
 * @tc.desc      : Test huks Verify (1024/SHA224withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest00900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_00900_PARAMS, sizeof(DSA_00900_PARAMS) / sizeof(DSA_00900_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA224), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA224 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01000
 * @tc.name      : HksDsaMtTest01000
 * @tc.desc      : Test huks Verify (1024/SHA224withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01000_PARAMS, sizeof(DSA_01000_PARAMS) / sizeof(DSA_01000_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslDsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslDsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateDsaKey(KEY_SIZE_1024);
    ASSERT_NE(pkey, nullptr);

    DsaGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveDsaKeyToHksBlob(pkey, KEY_SIZE_1024, &opensslDsaKeyInfo);

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &opensslDsaKeyInfo, HKS_DIGEST_SHA224), 0);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_ERROR_INVALID_ARGUMENT);
#else
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);
#endif
    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslDsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01100
 * @tc.name      : HksDsaMtTest01100
 * @tc.desc      : Test huks generate key (1024/SHA256withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01100_PARAMS, sizeof(DSA_01100_PARAMS) / sizeof(DSA_01100_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA256), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01200
 * @tc.name      : HksDsaMtTest01200
 * @tc.desc      : Test huks sign (1024/SHA256withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01200_PARAMS, sizeof(DSA_01200_PARAMS) / sizeof(DSA_01200_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA256), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01300
 * @tc.name      : HksDsaMtTest01300
 * @tc.desc      : Test huks sign (1024/SHA256withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01300_PARAMS, sizeof(DSA_01300_PARAMS) / sizeof(DSA_01300_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    uint8_t opensslDsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslDsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslDsaKeyInfo = { opensslDsaKeyLen, opensslDsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslDsaKeyInfo), HKS_SUCCESS);

    uint8_t dsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t dsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob dsaPublicKeyInfo = { dsaPublicKeyLen, dsaPublicKey };
    EXPECT_EQ(X509ToDsaPublicKey(&opensslDsaKeyInfo, &dsaPublicKeyInfo), 0);

    HksBlob publicKey = { .size = dsaPublicKeyInfo.size, .data = (uint8_t *)malloc(dsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, dsaPublicKeyInfo.data, dsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA256), 0);

    free(publicKey.data);
    free(signData.data);

#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01400
 * @tc.name      : HksDsaMtTest01400
 * @tc.desc      : Test huks Verify (1024/SHA256withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01400_PARAMS, sizeof(DSA_01400_PARAMS) / sizeof(DSA_01400_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA256), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01500
 * @tc.name      : HksDsaMtTest01500
 * @tc.desc      : Test huks Verify (1024/SHA256withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01500_PARAMS, sizeof(DSA_01500_PARAMS) / sizeof(DSA_01500_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslDsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslDsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateDsaKey(KEY_SIZE_1024);
    ASSERT_NE(pkey, nullptr);

    DsaGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveDsaKeyToHksBlob(pkey, KEY_SIZE_1024, &opensslDsaKeyInfo);

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &opensslDsaKeyInfo, HKS_DIGEST_SHA256), 0);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_ERROR_INVALID_ARGUMENT);
#else
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);
#endif
    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslDsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01600
 * @tc.name      : HksDsaMtTest01600
 * @tc.desc      : Test huks generate key (1024/SHA384withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01600, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01600_PARAMS, sizeof(DSA_01600_PARAMS) / sizeof(DSA_01600_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA384), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01700
 * @tc.name      : HksDsaMtTest01700
 * @tc.desc      : Test huks sign (1024/SHA384withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01700_PARAMS, sizeof(DSA_01700_PARAMS) / sizeof(DSA_01700_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA384), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01800
 * @tc.name      : HksDsaMtTest01800
 * @tc.desc      : Test huks sign (1024/SHA384withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01800_PARAMS, sizeof(DSA_01800_PARAMS) / sizeof(DSA_01800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    uint8_t opensslDsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslDsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslDsaKeyInfo = { opensslDsaKeyLen, opensslDsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslDsaKeyInfo), HKS_SUCCESS);

    uint8_t dsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t dsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob dsaPublicKeyInfo = { dsaPublicKeyLen, dsaPublicKey };
    EXPECT_EQ(X509ToDsaPublicKey(&opensslDsaKeyInfo, &dsaPublicKeyInfo), 0);

    HksBlob publicKey = { .size = dsaPublicKeyInfo.size, .data = (uint8_t *)malloc(dsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, dsaPublicKeyInfo.data, dsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA384), 0);

    free(publicKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_01900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest01900
 * @tc.name      : HksDsaMtTest01900
 * @tc.desc      : Test huks Verify (1024/SHA384withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest01900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_01900_PARAMS, sizeof(DSA_01900_PARAMS) / sizeof(DSA_01900_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA384), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_02000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest02000
 * @tc.name      : HksDsaMtTest02000
 * @tc.desc      : Test huks Verify (1024/SHA384withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest02000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, DSA_02000_PARAMS, sizeof(DSA_02000_PARAMS) / sizeof(DSA_02000_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslDsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslDsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateDsaKey(KEY_SIZE_1024);
    ASSERT_NE(pkey, nullptr);

    DsaGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveDsaKeyToHksBlob(pkey, KEY_SIZE_1024, &opensslDsaKeyInfo);

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &opensslDsaKeyInfo, HKS_DIGEST_SHA384), 0);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_ERROR_INVALID_ARGUMENT);
#else
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);
#endif
    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslDsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_02100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest02100
 * @tc.name      : HksDsaMtTest02100
 * @tc.desc      : Test huks generate key (1024/SHA512withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest02100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_02100_PARAMS, sizeof(DSA_02100_PARAMS) / sizeof(DSA_02100_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA512), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_02200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest02200
 * @tc.name      : HksDsaMtTest02200
 * @tc.desc      : Test huks sign (1024/SHA512withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest02200, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_02200_PARAMS, sizeof(DSA_02200_PARAMS) / sizeof(DSA_02200_PARAMS[0])),
        HKS_SUCCESS);
    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA512), 0);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_02300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest02300
 * @tc.name      : HksDsaMtTest02300
 * @tc.desc      : Test huks sign (1024/SHA512withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest02300, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_02300_PARAMS, sizeof(DSA_02300_PARAMS) / sizeof(DSA_02300_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
    EXPECT_EQ(HksGenerateKey(&authId, paramInSet, paramSetOut), HKS_SUCCESS);

    uint8_t opensslDsaKey[SET_SIZE_4096] = {0};
    uint32_t opensslDsaKeyLen = SET_SIZE_4096;
    struct HksBlob opensslDsaKeyInfo = { opensslDsaKeyLen, opensslDsaKey };
    EXPECT_EQ(HksExportPublicKey(&authId, paramInSet, &opensslDsaKeyInfo), HKS_SUCCESS);

    uint8_t dsaPublicKey[SET_SIZE_4096] = {0};
    uint32_t dsaPublicKeyLen = SET_SIZE_4096;
    struct HksBlob dsaPublicKeyInfo = { dsaPublicKeyLen, dsaPublicKey };
    EXPECT_EQ(X509ToDsaPublicKey(&opensslDsaKeyInfo, &dsaPublicKeyInfo), 0);

    HksBlob publicKey = { .size = dsaPublicKeyInfo.size, .data = (uint8_t *)malloc(dsaPublicKeyInfo.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, dsaPublicKeyInfo.data, dsaPublicKeyInfo.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyDsa(&plainText, &signData, &publicKey, HKS_DIGEST_SHA512), 0);

    free(publicKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_02400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest02400
 * @tc.name      : HksDsaMtTest02400
 * @tc.desc      : Test huks Verify (1024/SHA512withDSA/TEMP)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest02400, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, DSA_02400_PARAMS, sizeof(DSA_02400_PARAMS) / sizeof(DSA_02400_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_ERROR_NOT_SUPPORTED);
#else
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

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &privateKey, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
#endif
    free(paramSetOut);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam DSA_02500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksDsaMtTest02500
 * @tc.name      : HksDsaMtTest02500
 * @tc.desc      : Test huks Verify (1024/SHA512withDSA/PERSISTENT)
 */
HWTEST_F(HksDsaTestMT, HksDsaMtTest02500, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, DSA_02500_PARAMS, sizeof(DSA_02500_PARAMS) / sizeof(DSA_02500_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslDsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslDsaKeyInfo.data, nullptr);

    struct HksBlob x509Key = { 0, NULL };

    EVP_PKEY *pkey = GenerateDsaKey(KEY_SIZE_1024);
    ASSERT_NE(pkey, nullptr);

    DsaGetx509PubKey(pkey, &x509Key);

    EXPECT_EQ(HksImportKey(&authId, paramInSet, &x509Key), HKS_SUCCESS);

    SaveDsaKeyToHksBlob(pkey, KEY_SIZE_1024, &opensslDsaKeyInfo);

    EXPECT_EQ(OpensslSignDsa(&plainText, &signData, &opensslDsaKeyInfo, HKS_DIGEST_SHA512), 0);

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_ERROR_INVALID_ARGUMENT);
#else
    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);
#endif
    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslDsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace