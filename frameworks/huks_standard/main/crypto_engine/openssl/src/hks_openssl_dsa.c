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

#ifdef HKS_SUPPORT_DSA_GENERATE_KEY
static void DsaGetKeyParamLen(
    uint32_t keyLen, uint32_t *xlen, uint32_t *ylen, uint32_t *plen, uint32_t *qlen, uint32_t *glen)
{
    *xlen = (keyLen > OPENSSL_DSA_KEY_LEN_DIVID) ? HKS_DIGEST_SHA256_LEN : HKS_DIGEST_SHA1_LEN;
    *ylen = keyLen;
    *plen = keyLen;
    *qlen = (keyLen > OPENSSL_DSA_KEY_LEN_DIVID) ? HKS_DIGEST_SHA256_LEN : HKS_DIGEST_SHA1_LEN;
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
    keyMaterial->keySize = keyLen;
    DsaGetKeyParamLen(keyMaterial->keySize,
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
    output->data = (uint8_t *)HksMalloc(output->size);
    if (output->data == NULL) {
        HKS_LOG_E("malloc buffer failed");
        return HKS_ERROR_MALLOC_FAIL;
    }

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
#endif