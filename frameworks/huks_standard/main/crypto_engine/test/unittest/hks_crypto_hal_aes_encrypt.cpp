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
namespace {
class HksCryptoHalAesEncrypt : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalAesEncrypt_001
 * @tc.name      : HksCryptoHalAesEncrypt_001
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_001, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "933c213c1f8c844ffcc03f5f7e146a88";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_002
 * @tc.name      : HksCryptoHalAesEncrypt_002
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_002, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "933c213c1f8c844ffcc03f5f7e146a88";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_003
 * @tc.name      : HksCryptoHalAesEncrypt_003
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_003, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "933c213c1f8c844ffcc03f5f7e146a88";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_004
 * @tc.name      : HksCryptoHalAesEncrypt_004
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_004, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "933c213c1f8c844ffcc03f5f7e146a88";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_005
 * @tc.name      : HksCryptoHalAesEncrypt_005
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_005, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "933c213c1f8c844ffcc03f5f7e146a88";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
#endif
#if defined(_USE_MBEDTLS_)
    ASSERT_EQ(HKS_ERROR_NOT_SUPPORTED, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
#endif
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_006
 * @tc.name      : HksCryptoHalAesEncrypt_006
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_006, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "933c213c1f8c844ffcc03f5f7e146a88";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(tagAead.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_007
 * @tc.name      : HksCryptoHalAesEncrypt_007
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_007, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_008
 * @tc.name      : HksCryptoHalAesEncrypt_008
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_008, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_009
 * @tc.name      : HksCryptoHalAesEncrypt_009
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_009, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_010
 * @tc.name      : HksCryptoHalAesEncrypt_010
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_010, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_011
 * @tc.name      : HksCryptoHalAesEncrypt_011
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_011, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
#endif
#if defined(_USE_MBEDTLS_)
    ASSERT_EQ(HKS_ERROR_NOT_SUPPORTED, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
#endif
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_012
 * @tc.name      : HksCryptoHalAesEncrypt_012
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_012, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(tagAead.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_013
 * @tc.name      : HksCryptoHalAesEncrypt_013
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_013, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_014
 * @tc.name      : HksCryptoHalAesEncrypt_014
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_014, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_015
 * @tc.name      : HksCryptoHalAesEncrypt_015
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_015, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_016
 * @tc.name      : HksCryptoHalAesEncrypt_016
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_016, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_017
 * @tc.name      : HksCryptoHalAesEncrypt_017
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_017, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 0, .data = nullptr };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
#endif
#if defined(_USE_MBEDTLS_)
    ASSERT_EQ(HKS_ERROR_NOT_SUPPORTED, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
#endif
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_018
 * @tc.name      : HksCryptoHalAesEncrypt_018
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_018, Function | SmallTest | Level1)
{
    int32_t ret;

    const char *keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f";
    uint32_t keyLen = strlen(keyData) / 2;
    HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
    for (uint32_t ii = 0; ii < keyLen; ii++) {
        key.data[ii] = ReadHex((const uint8_t *)&keyData[2 * ii]);
    }

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

    HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };

    HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };

    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    HksFree(key.data);
    HksFree(message.data);
    HksFree(cipherText.data);
    HksFree(tagAead.data);
}
}  // namespace