/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <iostream>

#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace AesCipher {
namespace {
const char AES_128_GCM_KEY[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const char AES_192_GCM_KEY[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
}  // namespace
class HksCryptoHalAesCipher : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalAesCipher_001
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-CBC-NOPADDING key
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_001, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_002
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_002, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = (dataLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_003
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_003, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_004
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_004, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_005
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_005, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = (dataLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message));
    EXPECT_EQ(inscription.size, message.size);
    EXPECT_EQ(0, HksMemCmp(inscription.data, message.data, message.size));
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HKS_ERROR_NOT_SUPPORTED, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
#endif
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_006
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_006, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    struct HksAeadParam aeadParam;
    aeadParam.nonce = tagIv.iv;
    aeadParam.aad = { .size = 0, .data = nullptr };
    aeadParam.payloadLen = 0;
    aeadParam.tagLenEnc = 16;

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &aeadParam,
    };

    uint32_t dataLen = strlen(AES_128_GCM_KEY) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&AES_128_GCM_KEY[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&AES_128_GCM_KEY[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    aeadParam.tagDec = tagAead;
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message));
    EXPECT_EQ(inscription.size, message.size);
    EXPECT_EQ(0, HksMemCmp(inscription.data, message.data, message.size));
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
    HksFree(tagAead.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_007
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_007, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_008
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_008, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = (dataLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_009
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_009, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_010
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_010, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_011
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_011, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = (dataLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message));
    EXPECT_EQ(inscription.size, message.size);
    EXPECT_EQ(0, HksMemCmp(inscription.data, message.data, message.size));
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HKS_ERROR_NOT_SUPPORTED, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
#endif
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_012
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_012, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    struct HksAeadParam aeadParam;
    aeadParam.nonce = tagIv.iv;
    aeadParam.aad = { .size = 0, .data = nullptr };
    aeadParam.payloadLen = 0;
    aeadParam.tagLenEnc = 16;

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &aeadParam,
    };

    uint32_t dataLen = strlen(AES_192_GCM_KEY) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&AES_192_GCM_KEY[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&AES_192_GCM_KEY[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    aeadParam.tagDec = tagAead;
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message));
    EXPECT_EQ(inscription.size, message.size);
    EXPECT_EQ(0, HksMemCmp(inscription.data, message.data, message.size));
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(tagAead.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_013
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_013, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_014
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_014, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = (dataLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_015
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_015, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_016
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_016, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message);
    EXPECT_EQ(HKS_SUCCESS, ret);
    EXPECT_EQ(inscription.size, message.size);
    ret = HksMemCmp(inscription.data, message.data, message.size);
    EXPECT_EQ(0, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_017
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_017, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = (dataLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message));
    EXPECT_EQ(inscription.size, message.size);
    EXPECT_EQ(0, HksMemCmp(inscription.data, message.data, message.size));
#endif
#if defined(_USE_MBEDTLS_)
    EXPECT_EQ(HKS_ERROR_NOT_SUPPORTED, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
#endif
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_018
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_018, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };

    uint8_t iv[16] = {0};
    struct HksCipherParam tagIv;
    tagIv.iv = { .size = 16, .data = iv };
    struct HksAeadParam aeadParam;
    aeadParam.nonce = tagIv.iv;
    aeadParam.aad = { .size = 0, .data = nullptr };
    aeadParam.payloadLen = 0;
    aeadParam.tagLenEnc = 16;

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &aeadParam,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = dataLen;
    uint32_t inscriptionLen = dataLen;

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };

    HksBlob inscription = { .size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    aeadParam.tagDec = tagAead;
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalDecrypt(&key, &usageSpec, &cipherText, &message));
    EXPECT_EQ(inscription.size, message.size);
    EXPECT_EQ(0, HksMemCmp(inscription.data, message.data, message.size));
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(inscription.data);
    HksFree(tagAead.data);
}
}  // namespace AesCipher
