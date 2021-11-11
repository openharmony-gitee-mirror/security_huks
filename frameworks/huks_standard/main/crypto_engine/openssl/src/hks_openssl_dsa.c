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

#ifdef HKS_SUPPORT_DSA_C

#include "hks_openssl_dsa.h"

#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "hks_common_check.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_engine.h"
#include "hks_type_inner.h"

#define OPENSSL_KEY_BLOCK 8
#define OPENSSL_DSA_MIN_KEY_LEN 64
#define OPENSSL_DSA_KEY_LEN_DIVID (2048 / HKS_BITS_PER_BYTE)

static uint32_t GetOpensslKeyBlocksLen(uint32_t keylen)
{
    return (keylen + OPENSSL_KEY_BLOCK - 1) / OPENSSL_KEY_BLOCK * OPENSSL_KEY_BLOCK;
}

static DSA *InitDsaStruct(const struct HksBlob *key, const bool needPrivateExponent)
{
    DSA *dsa = DSA_new();
    if (dsa == NULL) {
        return NULL;
    }

    const struct KeyMaterialDsa *keyMaterial = (struct KeyMaterialDsa *)(key->data);
    uint8_t buff[HKS_KEY_BYTES(keyMaterial->keySize)];
    uint32_t offset = sizeof(*keyMaterial);
    BIGNUM *x = NULL;
    if (needPrivateExponent == true) {
        if (keyMaterial->xSize == 0) {
            return NULL;
        } else {
            (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->xSize);
            x = BN_bin2bn(buff, keyMaterial->xSize, NULL);
        }
    }
    offset += keyMaterial->xSize;
    (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->ySize);
    BIGNUM *y = BN_bin2bn(buff, keyMaterial->ySize, NULL);
    offset += keyMaterial->ySize;
    (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->pSize);
    BIGNUM *p = BN_bin2bn(buff, keyMaterial->pSize, NULL);
    offset += keyMaterial->pSize;
    (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->qSize);
    BIGNUM *q = BN_bin2bn(buff, keyMaterial->qSize, NULL);
    offset += keyMaterial->qSize;
    (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->gSize);
    BIGNUM *g = BN_bin2bn(buff, keyMaterial->gSize, NULL);

    if (DSA_set0_key(dsa, y, x) != HKS_OPENSSL_SUCCESS || DSA_set0_pqg(dsa, p, q, g) != HKS_OPENSSL_SUCCESS) {
        DSA_free(dsa);
        return NULL;
    }
    return dsa;
}

#ifdef HKS_SUPPORT_DSA_GENERATE_KEY
static void DsaGetKeyParamLen(
    uint32_t keyLen, uint32_t *xlen, uint32_t *ylen, uint32_t *plen, uint32_t *qlen, uint32_t *glen)
{
    *xlen = (keyLen >= OPENSSL_DSA_KEY_LEN_DIVID) ? HKS_DIGEST_SHA256_LEN : HKS_DIGEST_SHA1_LEN;
    *ylen = keyLen;
    *plen = keyLen;
    *qlen = (keyLen >= OPENSSL_DSA_KEY_LEN_DIVID) ? HKS_DIGEST_SHA256_LEN : HKS_DIGEST_SHA1_LEN;
    *glen = keyLen;
}

static uint32_t DsaCalculateMaterialLen(uint32_t keySize, uint32_t *dsaKeyLen)
{
    uint32_t opensslKeyByteLen = HKS_KEY_BYTES(keySize);
    if (opensslKeyByteLen < OPENSSL_DSA_MIN_KEY_LEN) {
        opensslKeyByteLen = OPENSSL_DSA_MIN_KEY_LEN;
    }

    opensslKeyByteLen = GetOpensslKeyBlocksLen(opensslKeyByteLen);

    uint32_t xlen = (opensslKeyByteLen > OPENSSL_DSA_KEY_LEN_DIVID) ? HKS_DIGEST_SHA256_LEN : HKS_DIGEST_SHA1_LEN;
    uint32_t ylen = opensslKeyByteLen;
    uint32_t plen = opensslKeyByteLen;
    uint32_t qlen = (opensslKeyByteLen > OPENSSL_DSA_KEY_LEN_DIVID) ? HKS_DIGEST_SHA256_LEN : HKS_DIGEST_SHA1_LEN;
    uint32_t glen = opensslKeyByteLen;
    DsaGetKeyParamLen(opensslKeyByteLen, &xlen, &ylen, &plen, &qlen, &glen);

    if (dsaKeyLen != NULL) {
        *dsaKeyLen = opensslKeyByteLen;
    }

    return sizeof(struct KeyMaterialDsa) + xlen + ylen + plen + qlen + glen;
}

static int32_t DsaKeyMaterialParam(uint8_t *rawMaterial, const DSA *dsa, uint32_t keyLen)
{
    struct KeyMaterialDsa *keyMaterial = (struct KeyMaterialDsa *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_DSA;
    keyMaterial->keySize = keyLen * HKS_BITS_PER_BYTE;
    DsaGetKeyParamLen(keyLen,
        &keyMaterial->xSize,
        &keyMaterial->ySize,
        &keyMaterial->pSize,
        &keyMaterial->qSize,
        &keyMaterial->gSize);
    return HKS_SUCCESS;
}

static int32_t DsaKeyMaterialData(uint8_t *rawMaterial, const DSA *dsa)
{
    int32_t ret;
    struct KeyMaterialDsa *keyMaterial = (struct KeyMaterialDsa *)rawMaterial;
    const BIGNUM *x = DSA_get0_priv_key(dsa);
    const BIGNUM *y = DSA_get0_pub_key(dsa);
    const BIGNUM *p = DSA_get0_p(dsa);
    const BIGNUM *q = DSA_get0_q(dsa);
    const BIGNUM *g = DSA_get0_g(dsa);

    int32_t offset = sizeof(struct KeyMaterialDsa);
    ret = BN_bn2bin(x, rawMaterial + offset + (keyMaterial->xSize - BN_num_bytes(x)));
    if (ret <= 0) {
        HksLogOpensslError();
        return HKS_FAILURE;
    }
    offset += keyMaterial->xSize;
    ret = BN_bn2bin(y, rawMaterial + offset + (keyMaterial->ySize - BN_num_bytes(y)));
    if (ret <= 0) {
        HksLogOpensslError();
        return HKS_FAILURE;
    }
    offset += keyMaterial->ySize;
    ret = BN_bn2bin(p, rawMaterial + offset + (keyMaterial->pSize - BN_num_bytes(p)));
    if (ret <= 0) {
        HksLogOpensslError();
        return HKS_FAILURE;
    }
    offset += keyMaterial->pSize;
    ret = BN_bn2bin(q, rawMaterial + offset + (keyMaterial->qSize - BN_num_bytes(q)));
    if (ret <= 0) {
        HksLogOpensslError();
        return HKS_FAILURE;
    }
    offset += keyMaterial->qSize;
    ret = BN_bn2bin(g, rawMaterial + offset + (keyMaterial->gSize - BN_num_bytes(g)));
    if (ret <= 0) {
        HksLogOpensslError();
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

static int32_t DsaSaveKeyMaterial(const DSA *dsa, const uint32_t keySize, uint8_t **output, uint32_t *outputSize)
{
    uint32_t keyLen;
    uint32_t rawMaterialLen = DsaCalculateMaterialLen(keySize, &keyLen);
    uint8_t *rawMaterial = (uint8_t *)HksMalloc(rawMaterialLen);
    if (rawMaterial == NULL) {
        HKS_LOG_E("malloc buffer failed!");
        return HKS_ERROR_MALLOC_FAIL;
    }

    if (DsaKeyMaterialParam(rawMaterial, dsa, keyLen) != HKS_SUCCESS) {
        HksFree(rawMaterial);
        return HKS_FAILURE;
    }
    if (DsaKeyMaterialData(rawMaterial, dsa) != HKS_SUCCESS) {
        HksFree(rawMaterial);
        return HKS_FAILURE;
    }

    *output = rawMaterial;
    *outputSize = rawMaterialLen;
    return HKS_SUCCESS;
}

int32_t HksOpensslDsaGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    int32_t ret;
    if (spec->keyLen % HKS_BITS_PER_BYTE != 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    DSA *dsa = DSA_new();
    if (dsa == NULL) {
        HKS_LOG_E("DSA structure is NULL.");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    do {
        ret = DSA_generate_parameters_ex(dsa, spec->keyLen, NULL, 0, NULL, NULL, NULL);
        if (ret != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        ret = DSA_generate_key(dsa);
        if (ret != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        ret = DsaSaveKeyMaterial(dsa, spec->keyLen, &key->data, &key->size);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("save dsa key material failed! ret=0x%x", ret);
            break;
        }
    } while (0);

    if (dsa != NULL) {
        DSA_free(dsa);
    }

    return ret;
}
#endif

#ifdef HKS_SUPPORT_DSA_GET_PUBLIC_KEY
int32_t HksOpensslGetDsaPubKey(const struct HksBlob *input, struct HksBlob *output)
{
    struct KeyMaterialDsa *keyMaterial = (struct KeyMaterialDsa *)input->data;

    output->size = sizeof(struct KeyMaterialDsa) + keyMaterial->ySize + keyMaterial->pSize + keyMaterial->qSize +
                   keyMaterial->gSize;

    struct KeyMaterialDsa *publickeyMaterial = (struct KeyMaterialDsa *)output->data;
    publickeyMaterial->keyAlg = keyMaterial->keyAlg;
    publickeyMaterial->keySize = keyMaterial->keySize;
    publickeyMaterial->xSize = 0;
    publickeyMaterial->ySize = keyMaterial->ySize;
    publickeyMaterial->pSize = keyMaterial->pSize;
    publickeyMaterial->qSize = keyMaterial->qSize;
    publickeyMaterial->gSize = keyMaterial->gSize;

    memcpy_s(output->data + sizeof(struct KeyMaterialDsa) + publickeyMaterial->xSize,
        output->size - (sizeof(struct KeyMaterialDsa) + publickeyMaterial->xSize),
        input->data + sizeof(struct KeyMaterialDsa) + keyMaterial->xSize,
        keyMaterial->ySize + keyMaterial->pSize + keyMaterial->qSize + keyMaterial->gSize);

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_DSA_SIGN_VERIFY
static EVP_MD_CTX *InitDSAMdCtx(const struct HksBlob *key, const struct HksUsageSpec *usageSpec, bool signing)
{
    int32_t ret;

    DSA *dsa = InitDsaStruct(key, signing);
    if (dsa == NULL) {
        HKS_LOG_E("initialize dsa key failed");
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        HksLogOpensslError();
        DSA_free(dsa);
        return NULL;
    }

    if (EVP_PKEY_assign_DSA(pkey, dsa) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        DSA_free(dsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        HksLogOpensslError();
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (signing) {
        ret = EVP_DigestSignInit(ctx, NULL, GetOpensslAlg(usageSpec->digest), NULL, pkey);
    } else {
        ret = EVP_DigestVerifyInit(ctx, NULL, GetOpensslAlg(usageSpec->digest), NULL, pkey);
    }
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_free(pkey);

    return ctx;
}

int32_t HksOpensslDsaSign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    EVP_MD_CTX *ctx = InitDSAMdCtx(key, usageSpec, true);
    if (ctx == NULL) {
        HKS_LOG_E("initialize ecc md context failed");
        return HKS_ERROR_INVALID_KEY_INFO;
    }

    if (EVP_DigestSignUpdate(ctx, message->data, message->size) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_MD_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    size_t outLen = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &outLen) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_MD_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (outLen > signature->size) {
        HksLogOpensslError();
        EVP_MD_CTX_free(ctx);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    if (EVP_DigestSignFinal(ctx, signature->data, &outLen) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_MD_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    signature->size = outLen;

    EVP_MD_CTX_free(ctx);

    return HKS_SUCCESS;
}

int32_t HksOpensslDsaVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    EVP_MD_CTX *ctx = InitDSAMdCtx(key, usageSpec, false);
    if (ctx == NULL) {
        HKS_LOG_E("initialize ecc md context failed");
        return HKS_ERROR_INVALID_KEY_INFO;
    }

    if (EVP_DigestVerifyUpdate(ctx, message->data, message->size) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_MD_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (EVP_DigestVerifyFinal(ctx, signature->data, signature->size) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_MD_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    EVP_MD_CTX_free(ctx);

    return HKS_SUCCESS;
}
#endif
#endif
