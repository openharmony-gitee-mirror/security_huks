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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifdef HKS_SUPPORT_RSA_C

#include "hks_openssl_rsa.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_engine.h"
#include "hks_type_inner.h"

static int32_t RsaGenKeyCheckParam(const struct HksKeySpec *spec)
{
    switch (spec->keyLen) {
        case HKS_RSA_KEY_SIZE_512:
        case HKS_RSA_KEY_SIZE_768:
        case HKS_RSA_KEY_SIZE_1024:
        case HKS_RSA_KEY_SIZE_2048:
        case HKS_RSA_KEY_SIZE_3072:
        case HKS_RSA_KEY_SIZE_4096:
            return HKS_SUCCESS;
        default:
            HKS_LOG_E("Invlid rsa key len %x!", spec->keyLen);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

static int32_t GetRsaPadding(uint32_t padding, uint32_t *rsaPadding)
{
    switch (padding) {
        case HKS_PADDING_NONE:
            *rsaPadding = RSA_NO_PADDING;
            return HKS_SUCCESS;
        case HKS_PADDING_PKCS1_V1_5:
            *rsaPadding = RSA_PKCS1_PADDING;
            return HKS_SUCCESS;
        case HKS_PADDING_OAEP:
            *rsaPadding = RSA_PKCS1_OAEP_PADDING;
            return HKS_SUCCESS;
        default:
            return HKS_FAILURE;
    }
}

static RSA *InitRsaStruct(const struct HksBlob *key, const bool needPrivateExponent)
{
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);
    uint8_t buff[HKS_KEY_BYTES(keyMaterial->keySize)];

    uint32_t offset = sizeof(*keyMaterial);
    (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->nSize);
    BIGNUM *n = BN_bin2bn(buff, keyMaterial->nSize, NULL);
    offset += keyMaterial->nSize;
    (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->eSize);
    BIGNUM *e = BN_bin2bn(buff, keyMaterial->eSize, NULL);
    offset += keyMaterial->eSize;
    BIGNUM *d = NULL;
    if (needPrivateExponent) {
        (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->dSize);
        d = BN_bin2bn(buff, keyMaterial->dSize, NULL);
    }

    RSA *rsa = RSA_new();
    int32_t ret = RSA_set0_key(rsa, n, e, d);
    if (ret != HKS_OPENSSL_SUCCESS) {
        return NULL;
    }

    return rsa;
}

#ifdef HKS_SUPPORT_RSA_GENERATE_KEY
static int32_t RsaSaveKeyMaterial(const RSA *rsa, const uint32_t keySize, struct HksBlob *key)
{
    const uint32_t keyByteLen = keySize / HKS_BITS_PER_BYTE;
    const uint32_t rawMaterialLen = sizeof(struct KeyMaterialRsa) + keyByteLen * HKS_RSA_KEYPAIR_CNT;
    uint8_t *rawMaterial = (uint8_t *)HksMalloc(rawMaterialLen);
    if (rawMaterial == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_RSA;
    keyMaterial->keySize = keySize;

    uint8_t tmp_buff[keyByteLen];
    memset_s(tmp_buff, keyByteLen, 0x00, keyByteLen);

    uint32_t offset = sizeof(*keyMaterial);
    keyMaterial->nSize = BN_bn2bin(RSA_get0_n(rsa), tmp_buff);
    memcpy_s(rawMaterial + offset, keyByteLen, tmp_buff, keyMaterial->nSize);

    offset += keyMaterial->nSize;
    keyMaterial->eSize = BN_bn2bin(RSA_get0_e(rsa), tmp_buff);
    memcpy_s(rawMaterial + offset, keyByteLen, tmp_buff, keyMaterial->eSize);

    offset += keyMaterial->eSize;
    keyMaterial->dSize = BN_bn2bin(RSA_get0_d(rsa), tmp_buff);
    memcpy_s(rawMaterial + offset, keyByteLen, tmp_buff, keyMaterial->dSize);

    key->data = rawMaterial;
    key->size = rawMaterialLen;

    return HKS_SUCCESS;
}

int32_t HksOpensslRsaGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    if (RsaGenKeyCheckParam(spec) != HKS_SUCCESS) {
        HKS_LOG_E("rsa generate key invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    BN_set_word(e, RSA_F4);

    RSA_generate_key_ex(rsa, spec->keyLen, e, NULL);

    int32_t ret = RsaSaveKeyMaterial(rsa, spec->keyLen, key);

    BN_free(e);
    RSA_free(rsa);

    return ret;
}
#endif

#ifdef HKS_SUPPORT_RSA_GET_PUBLIC_KEY
int32_t HksOpensslGetRsaPubKey(const struct HksBlob *input, struct HksBlob *output)
{
    struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)input->data;
    output->size = sizeof(struct KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize;
    output->data = (uint8_t *)HksMalloc(output->size);
    if (output->data == NULL) {
        HKS_LOG_E("malloc buffer failed");
        return HKS_ERROR_MALLOC_FAIL;
    }

    struct KeyMaterialRsa *publickeyMaterial = (struct KeyMaterialRsa *)output->data;
    publickeyMaterial->keyAlg = keyMaterial->keyAlg;
    publickeyMaterial->keySize = keyMaterial->keySize;
    publickeyMaterial->nSize = keyMaterial->nSize;
    publickeyMaterial->eSize = keyMaterial->eSize;
    publickeyMaterial->dSize = 0;

    memcpy_s(output->data + sizeof(struct KeyMaterialRsa),
        output->size - sizeof(struct KeyMaterialRsa),
        input->data + sizeof(struct KeyMaterialRsa),
        keyMaterial->nSize + keyMaterial->eSize);

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_RSA_CRYPT
static EVP_PKEY_CTX *InitEvpPkeyCtx(const struct HksBlob *key, bool encrypt)
{
    int32_t ret;
    RSA *rsa = InitRsaStruct(key, !encrypt);
    if (rsa == NULL) {
        HKS_LOG_E("initialize rsa key failed");
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        HksLogOpensslError();
        return NULL;
    }

    ret = EVP_PKEY_assign_RSA(pkey, rsa);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_free(pkey);
        return NULL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        HksLogOpensslError();
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (encrypt) {
        ret = EVP_PKEY_encrypt_init(ctx);
    } else {
        ret = EVP_PKEY_decrypt_init(ctx);
    }
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return ctx;
}

static int32_t HksOpensslRsaCryptInit(EVP_PKEY_CTX *ctx, const struct HksUsageSpec *usageSpec)
{
    int32_t ret;
    uint32_t padding = 0;
    if (GetRsaPadding(usageSpec->padding, &padding) != HKS_SUCCESS) {
        HKS_LOG_E("Unsupport padding.");
        return HKS_FAILURE;
    }

    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, padding);
    if (ret <= 0) {
        HksLogOpensslError();
        return HKS_FAILURE;
    }

    if (usageSpec->padding == HKS_PADDING_OAEP) {
        const EVP_MD *md = GetOpensslAlg(usageSpec->digest);
        if (md == NULL || EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0 || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
            HksLogOpensslError();
            return HKS_FAILURE;
        }
    }
    return HKS_SUCCESS;
}

int32_t HksOpensslRsaCrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    int32_t ret;
    EVP_PKEY_CTX *ctx = InitEvpPkeyCtx(key, encrypt);
    if (ctx == NULL) {
        HksLogOpensslError();
        return HKS_FAILURE;
    }

    if (HksOpensslRsaCryptInit(ctx, usageSpec) != HKS_SUCCESS) {
        EVP_PKEY_CTX_free(ctx);
        return HKS_FAILURE;
    }

    size_t outLen;
    if (encrypt) {
        ret = EVP_PKEY_encrypt(ctx, NULL, &outLen, message->data, message->size);
    } else {
        ret = EVP_PKEY_decrypt(ctx, NULL, &outLen, message->data, message->size);
    }
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_FAILURE;
    }

    if (outLen > cipherText->size) {
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_FAILURE;
    }

    if (encrypt) {
        ret = EVP_PKEY_encrypt(ctx, cipherText->data, &outLen, message->data, message->size);
    } else {
        ret = EVP_PKEY_decrypt(ctx, cipherText->data, &outLen, message->data, message->size);
    }
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_FAILURE;
    }
    cipherText->size = outLen;

    return HKS_SUCCESS;
}
#endif
#endif