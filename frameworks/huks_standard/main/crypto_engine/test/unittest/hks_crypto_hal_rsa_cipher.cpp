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
namespace RsaCipher {
namespace {
const char RSA_2048_NOPADDING_KEY[] =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000";
const char RSA_3072_NOPADDING_KEY[] =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const char RSA_4096_NOPADDING_KEY[] =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000";
}  // namespace
class HksCryptoHalRsaCipher : public HksCryptoHalCommon, public testing::Test {};

/**
 * @tc.number    : HksCryptoHalRsaCipher_001
 * @tc.name      : HksCryptoHalRsaCipher_001
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-512-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_001, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff000000000000000000000000000"
                          "0000000000000000000000000000000000000";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_512);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_002
 * @tc.name      : HksCryptoHalRsaCipher_002
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-768-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_002, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_768);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_003
 * @tc.name      : HksCryptoHalRsaCipher_003
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-1024-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_003, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff000000000000000000000000000"
                          "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                          "00000000000000000000000000000000000000000000000000000000000000000000000000";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_1024);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_004
 * @tc.name      : HksCryptoHalRsaCipher_004
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-2048-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_004, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    uint32_t dataLen = strlen(RSA_2048_NOPADDING_KEY) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_2048);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&RSA_2048_NOPADDING_KEY[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&RSA_2048_NOPADDING_KEY[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_005
 * @tc.name      : HksCryptoHalRsaCipher_005
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-3072-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_005, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    uint32_t dataLen = strlen(RSA_3072_NOPADDING_KEY) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_3072);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&RSA_3072_NOPADDING_KEY[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&RSA_3072_NOPADDING_KEY[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_006
 * @tc.name      : HksCryptoHalRsaCipher_006
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-4096-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_006, Function | SmallTest | Level1)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    uint32_t dataLen = strlen(RSA_4096_NOPADDING_KEY) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&RSA_4096_NOPADDING_KEY[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&RSA_4096_NOPADDING_KEY[2 * ii]);
    }

    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalGenerateKey(&spec, &key));
#if defined(_USE_OPENSSL_)
    EXPECT_EQ(HKS_SUCCESS, HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead));
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_007
 * @tc.name      : HksCryptoHalRsaCipher_007
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-512-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_007, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_512);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_008
 * @tc.name      : HksCryptoHalRsaCipher_008
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-768-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_008, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_768);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_009
 * @tc.name      : HksCryptoHalRsaCipher_009
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-1024-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_009, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_1024);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_010
 * @tc.name      : HksCryptoHalRsaCipher_010
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-2048-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_010, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_2048);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_011
 * @tc.name      : HksCryptoHalRsaCipher_011
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-3072-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_011, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_3072);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_012
 * @tc.name      : HksCryptoHalRsaCipher_012
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-4096-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_012, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_013
 * @tc.name      : HksCryptoHalRsaCipher_013
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-512-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_013, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccdd";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_512);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_014
 * @tc.name      : HksCryptoHalRsaCipher_014
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-768-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_014, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_768);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_015
 * @tc.name      : HksCryptoHalRsaCipher_015
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-1024-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_015, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_1024);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_016
 * @tc.name      : HksCryptoHalRsaCipher_016
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-2048-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_016, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_2048);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_017
 * @tc.name      : HksCryptoHalRsaCipher_017
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-3072-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_017, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_3072);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_018
 * @tc.name      : HksCryptoHalRsaCipher_018
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-4096-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_018, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_019
 * @tc.name      : HksCryptoHalRsaCipher_019
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-512-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_019, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "001122334455";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_512);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_020
 * @tc.name      : HksCryptoHalRsaCipher_020
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-768-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_020, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_768);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_021
 * @tc.name      : HksCryptoHalRsaCipher_021
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-1024-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_021, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_1024);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_022
 * @tc.name      : HksCryptoHalRsaCipher_022
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-2048-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_022, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_2048);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_023
 * @tc.name      : HksCryptoHalRsaCipher_023
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-3072-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_023, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_3072);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_024
 * @tc.name      : HksCryptoHalRsaCipher_024
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-4096-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_024, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_025
 * @tc.name      : HksCryptoHalRsaCipher_025
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-768-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_025, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "001122334455";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_768);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_026
 * @tc.name      : HksCryptoHalRsaCipher_026
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-1024-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_026, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_1024);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_027
 * @tc.name      : HksCryptoHalRsaCipher_027
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-2048-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_027, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_2048);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_028
 * @tc.name      : HksCryptoHalRsaCipher_028
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-3072-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_028, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_3072);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_029
 * @tc.name      : HksCryptoHalRsaCipher_029
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-4096-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_029, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_030
 * @tc.name      : HksCryptoHalRsaCipher_030
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-1024-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_030, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "001122334455";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_1024);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_031
 * @tc.name      : HksCryptoHalRsaCipher_031
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-2048-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_031, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_2048);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_032
 * @tc.name      : HksCryptoHalRsaCipher_032
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-3072-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_032, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_3072);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_033
 * @tc.name      : HksCryptoHalRsaCipher_033
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-4096-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_033, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccdd";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_034
 * @tc.name      : HksCryptoHalRsaCipher_034
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-2048-OAEP_SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_034, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccdd";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_2048);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_035
 * @tc.name      : HksCryptoHalRsaCipher_035
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-3072-OAEP_SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_035, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccdd";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_3072);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
 * @tc.number    : HksCryptoHalRsaCipher_036
 * @tc.name      : HksCryptoHalRsaCipher_036
 * @tc.desc      : Generate key and Encrypt / Decrypt RSA-4096-OAEP_SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaCipher, HksCryptoHalRsaCipher_036, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    };

    HksBlob key = {.size = 0, .data = nullptr};

    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };

    const char *hexData = "00112233445566778899aabbccdd";
    uint32_t dataLen = strlen(hexData) / 2;

    uint32_t inLen = dataLen;
    uint32_t outLen = HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096);
    uint32_t inscriptionLen = dataLen;

    HksBlob message = {.size = inLen, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    HksBlob cipherText = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};

    HksBlob tagAead = {.size = 0, .data = nullptr};

    HksBlob inscription = {.size = inscriptionLen, .data = (uint8_t *)HksMalloc(inscriptionLen)};
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        inscription.data[ii] = ReadHex((const uint8_t *)&hexData[2 * ii]);
    }

    ret = HksCryptoHalGenerateKey(&spec, &key);
    EXPECT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalEncrypt(&key, &usageSpec, &message, &cipherText, &tagAead);
    EXPECT_EQ(HKS_SUCCESS, ret);
    message = {.size = outLen, .data = (uint8_t *)HksMalloc(outLen)};
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
}  // namespace RsaCipher