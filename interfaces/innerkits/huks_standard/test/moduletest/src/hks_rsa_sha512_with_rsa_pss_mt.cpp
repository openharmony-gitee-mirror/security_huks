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
const char TEST_KEY_AUTH_ID[] = "This is a test auth id for Sha512AndPss";
const int SET_SIZE_4096 = 4096;
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;
}  // namespace

class HksRsaSha512WithRsaPssMt : public testing::Test {};

static const struct HksParam RSA_50500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest50500
 * @tc.name      : HksRsaMtTest50500
 * @tc.desc      : Test huks sign (512/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest50500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_50500_PARAMS, sizeof(RSA_50500_PARAMS) / sizeof(RSA_50500_PARAMS[0])),
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

#if (defined(_USE_OPENSSL_) || defined(_USE_MBEDTLS_))
    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_ERROR_CRYPTO_ENGINE_ERROR);
#else
    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_SUCCESS);
    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_50600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest50600
 * @tc.name      : HksRsaMtTest50600
 * @tc.desc      : Test huks sign (512/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest50600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_50600_PARAMS, sizeof(RSA_50600_PARAMS) / sizeof(RSA_50600_PARAMS[0])),
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

#if (defined(_USE_OPENSSL_) || defined(_USE_MBEDTLS_))
    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_ERROR_CRYPTO_ENGINE_ERROR);
#else
    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);
    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_50700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest50700
 * @tc.name      : HksRsaMtTest50700
 * @tc.desc      : Test huks Verify (512/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest50700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_50700_PARAMS, sizeof(RSA_50700_PARAMS) / sizeof(RSA_50700_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    EXPECT_EQ(HksGenerateKey(NULL, paramInSet, paramSetOut), HKS_SUCCESS);

    HksParam *priKeyExport = NULL;
    EXPECT_EQ(HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyExport), HKS_SUCCESS);

    HksBlob privateKey = { .size = priKeyExport->blob.size, .data = (uint8_t *)malloc(priKeyExport->blob.size) };
    ASSERT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, priKeyExport->blob.size, priKeyExport->blob.data, priKeyExport->blob.size);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), RSA_FAILED);

    free(paramSetOut);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_50800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest50800
 * @tc.name      : HksRsaMtTest50800
 * @tc.desc      : Test huks Verify (512/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest50800, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_50800_PARAMS, sizeof(RSA_50800_PARAMS) / sizeof(RSA_50800_PARAMS[0])),
        HKS_SUCCESS);

    EXPECT_EQ(HksBuildParamSet(&paramInSet), HKS_SUCCESS);

    const char *hexData = "00112233445566778899aabbccddeeff";

    HksBlob plainText = { .size = strlen(hexData), .data = (uint8_t *)hexData };

    HksBlob signData = { .size = SET_SIZE_4096, .data = (uint8_t *)malloc(SET_SIZE_4096) };
    ASSERT_NE(signData.data, nullptr);

    struct HksBlob opensslRsaKeyInfo = { .size = SET_SIZE_4096, .data = (uint8_t *)calloc(1, SET_SIZE_4096) };
    ASSERT_NE(opensslRsaKeyInfo.data, nullptr);

    EVP_PKEY *pkey = GenerateRSAKey(KEY_SIZE_512);
    ASSERT_NE(pkey, nullptr);

    SaveRsaKeyToHksBlob(pkey, KEY_SIZE_512, &opensslRsaKeyInfo);

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512),
        RSA_FAILED);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_50900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest50900
 * @tc.name      : HksRsaMtTest50900
 * @tc.desc      : Test huks sign (768/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest50900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_50900_PARAMS, sizeof(RSA_50900_PARAMS) / sizeof(RSA_50900_PARAMS[0])),
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

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_ERROR_CRYPTO_ENGINE_ERROR);
#else
    EXPECT_EQ(HksSign(&privateKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51000
 * @tc.name      : HksRsaMtTest51000
 * @tc.desc      : Test huks sign (768/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51000_PARAMS, sizeof(RSA_51000_PARAMS) / sizeof(RSA_51000_PARAMS[0])),
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

#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_ERROR_CRYPTO_ENGINE_ERROR);
#else
    EXPECT_EQ(HksSign(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);
#endif

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51100
 * @tc.name      : HksRsaMtTest51100
 * @tc.desc      : Test huks Verify (768/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51100_PARAMS, sizeof(RSA_51100_PARAMS) / sizeof(RSA_51100_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51200
 * @tc.name      : HksRsaMtTest51200
 * @tc.desc      : Test huks Verify (768/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51200_PARAMS, sizeof(RSA_51200_PARAMS) / sizeof(RSA_51200_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51300
 * @tc.name      : HksRsaMtTest51300
 * @tc.desc      : Test huks sign (1024/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51300_PARAMS, sizeof(RSA_51300_PARAMS) / sizeof(RSA_51300_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51400
 * @tc.name      : HksRsaMtTest51400
 * @tc.desc      : Test huks sign (1024/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51400_PARAMS, sizeof(RSA_51400_PARAMS) / sizeof(RSA_51400_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51500
 * @tc.name      : HksRsaMtTest51500
 * @tc.desc      : Test huks Verify (1024/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51500_PARAMS, sizeof(RSA_51500_PARAMS) / sizeof(RSA_51500_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51600
 * @tc.name      : HksRsaMtTest51600
 * @tc.desc      : Test huks Verify (1024/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51600_PARAMS, sizeof(RSA_51600_PARAMS) / sizeof(RSA_51600_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51700
 * @tc.name      : HksRsaMtTest51700
 * @tc.desc      : Test huks sign (2048/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51700_PARAMS, sizeof(RSA_51700_PARAMS) / sizeof(RSA_51700_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51800
 * @tc.name      : HksRsaMtTest51800
 * @tc.desc      : Test huks sign (2048/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51800_PARAMS, sizeof(RSA_51800_PARAMS) / sizeof(RSA_51800_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_51900_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest51900
 * @tc.name      : HksRsaMtTest51900
 * @tc.desc      : Test huks Verify (2048/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest51900, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_51900_PARAMS, sizeof(RSA_51900_PARAMS) / sizeof(RSA_51900_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_52000_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest52000
 * @tc.name      : HksRsaMtTest52000
 * @tc.desc      : Test huks Verify (2048/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest52000, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_52000_PARAMS, sizeof(RSA_52000_PARAMS) / sizeof(RSA_52000_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_52100_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest52100
 * @tc.name      : HksRsaMtTest52100
 * @tc.desc      : Test huks sign (3072/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest52100, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_52100_PARAMS, sizeof(RSA_52100_PARAMS) / sizeof(RSA_52100_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_52200_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest52200
 * @tc.name      : HksRsaMtTest52200
 * @tc.desc      : Test huks sign (3072/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest52200, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_52200_PARAMS, sizeof(RSA_52200_PARAMS) / sizeof(RSA_52200_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_52300_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest52300
 * @tc.name      : HksRsaMtTest52300
 * @tc.desc      : Test huks Verify (3072/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest52300, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_52300_PARAMS, sizeof(RSA_52300_PARAMS) / sizeof(RSA_52300_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_52400_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest52400
 * @tc.name      : HksRsaMtTest52400
 * @tc.desc      : Test huks Verify (3072/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest52400, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_52400_PARAMS, sizeof(RSA_52400_PARAMS) / sizeof(RSA_52400_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_52500_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest52500
 * @tc.name      : HksRsaMtTest52500
 * @tc.desc      : Test huks sign (4096/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest52500, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_52500_PARAMS, sizeof(RSA_52500_PARAMS) / sizeof(RSA_52500_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_52600_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest52600
 * @tc.name      : HksRsaMtTest52600
 * @tc.desc      : Test huks sign (4096/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest52600, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_52600_PARAMS, sizeof(RSA_52600_PARAMS) / sizeof(RSA_52600_PARAMS[0])),
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

    EXPECT_EQ(OpensslVerifyRsa(&plainText, &signData, &publicKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    free(paramSetOut);
    free(publicKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_52700_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest52700
 * @tc.name      : HksRsaMtTest52700
 * @tc.desc      : Test huks Verify (4096/SHA512withRSA/PSS/TEMP)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest52700, TestSize.Level1)
{
    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    struct HksParamSet *paramSetOut = (struct HksParamSet *)malloc(SET_SIZE_4096);
    ASSERT_NE(paramSetOut, nullptr);
    (void)memset_s(paramSetOut, SET_SIZE_4096, 0, SET_SIZE_4096);
    paramSetOut->paramSetSize = SET_SIZE_4096;

    EXPECT_EQ(HksAddParams(paramInSet, RSA_52700_PARAMS, sizeof(RSA_52700_PARAMS) / sizeof(RSA_52700_PARAMS[0])),
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

    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &privateKey, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&publicKey, paramInSet, &plainText, &signData), HKS_SUCCESS);

    free(paramSetOut);
    free(publicKey.data);
    free(privateKey.data);
    free(signData.data);
    HksFreeParamSet(&paramInSet);
}

static const struct HksParam RSA_52800_PARAMS[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
};

/**
 * @tc.number    : HksRsaMtTest52800
 * @tc.name      : HksRsaMtTest52800
 * @tc.desc      : Test huks Verify (4096/SHA512withRSA/PSS/PERSISTENT)
 */
HWTEST_F(HksRsaSha512WithRsaPssMt, HksRsaMtTest52800, TestSize.Level1)
{
    struct HksBlob authId = { strlen(TEST_KEY_AUTH_ID), (uint8_t *)TEST_KEY_AUTH_ID };

    struct HksParamSet *paramInSet = NULL;
    HksInitParamSet(&paramInSet);
    ASSERT_NE(paramInSet, nullptr);

    EXPECT_EQ(HksAddParams(paramInSet, RSA_52800_PARAMS, sizeof(RSA_52800_PARAMS) / sizeof(RSA_52800_PARAMS[0])),
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
    EXPECT_EQ(OpensslSignRsa(&plainText, &signData, &opensslRsaKeyInfo, RSA_PKCS1_PSS_PADDING, HKS_DIGEST_SHA512), 0);

    EXPECT_EQ(HksVerify(&authId, paramInSet, &plainText, &signData), HKS_SUCCESS);

    EVP_PKEY_free(pkey);
    free(signData.data);
    free(opensslRsaKeyInfo.data);
    HksFreeParamSet(&paramInSet);
}
}  // namespace