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

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "hks_crypto_hal.h"
#include "hks_common_check.h"

#define OPENSSL_KEY_BLOCK 8
#define OPENSSL_DSA_MIN_KEY_LEN 64
#define OPENSSL_DSA_KEY_LEN_DIVID (2048 / HKS_BITS_PER_BYTE)

EVP_PKEY *GenerateDsaKey(const uint32_t keySize)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        return NULL;
    }
    DSA *dsa = DSA_new();
    if (dsa == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if (DSA_generate_parameters_ex(dsa, keySize, NULL, 0, NULL, NULL, NULL) != 1) {
        EVP_PKEY_free(pkey);
        DSA_free(dsa);
        return NULL;
    }
    if (DSA_generate_key(dsa) != 1) {
        EVP_PKEY_free(pkey);
        DSA_free(dsa);
        return NULL;
    }

    EVP_PKEY_assign_DSA(pkey, dsa);

    return pkey;
}

static DSA *InitDsa(struct HksBlob *key, const bool needPrivateExponent)
{
    const struct KeyMaterialDsa *keyMaterial = (struct KeyMaterialDsa *)(key->data);
    uint8_t buff[HKS_KEY_BYTES(keyMaterial->keySize)];

    uint32_t offset = sizeof(*keyMaterial);
    BIGNUM *x = NULL;
    if (needPrivateExponent) {
        (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->xSize);
        x = BN_bin2bn(buff, keyMaterial->xSize, NULL);
    }

    offset += keyMaterial->xSize;
    if (memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->ySize) != 0) {
        return NULL;
    }
    BIGNUM *y = BN_bin2bn(buff, keyMaterial->ySize, NULL);

    offset += keyMaterial->ySize;
    if (memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->pSize) != 0) {
        return NULL;
    }
    BIGNUM *p = BN_bin2bn(buff, keyMaterial->pSize, NULL);

    offset += keyMaterial->pSize;
    if (memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->qSize) != 0) {
        return NULL;
    }
    BIGNUM *q = BN_bin2bn(buff, keyMaterial->qSize, NULL);

    offset += keyMaterial->qSize;
    if (memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->gSize) != 0) {
        return NULL;
    }
    BIGNUM *g = BN_bin2bn(buff, keyMaterial->gSize, NULL);

    DSA *dsa = DSA_new();
    if (DSA_set0_key(dsa, y, x) != 1 || DSA_set0_pqg(dsa, p, q, g) != 1) {
        return NULL;
    }

    return dsa;
}

static const EVP_MD *GetOpensslDigestType(enum HksKeyDigest digestType)
{
    switch (digestType) {
        case HKS_DIGEST_MD5:
            return EVP_md5();
        case HKS_DIGEST_SHA1:
            return EVP_sha1();
        case HKS_DIGEST_SHA224:
            return EVP_sha224();
        case HKS_DIGEST_SHA256:
            return EVP_sha256();
        case HKS_DIGEST_SHA384:
            return EVP_sha384();
        case HKS_DIGEST_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

int32_t OpensslSignDsa(
    const struct HksBlob *plainText, struct HksBlob *signData, struct HksBlob *key, enum HksKeyDigest digestType)
{
    DSA *dsa = InitDsa(key, true);
    if (dsa == NULL) {
        return DSA_FAILED;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        EVP_PKEY_free(pkey);
        return DSA_FAILED;
    }

    EVP_PKEY_assign_DSA(pkey, dsa);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        EVP_MD_CTX_free(mctx);
        return DSA_FAILED;
    }

    const EVP_MD *md = GetOpensslDigestType(digestType);
    if (EVP_DigestSignInit(mctx, NULL, md, NULL, pkey) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mctx);
        return DSA_FAILED;
    }

    if (EVP_DigestSignUpdate(mctx, plainText->data, plainText->size) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return DSA_FAILED;
    }

    size_t signLen = signData->size;
    if (EVP_DigestSignFinal(mctx, signData->data, &signLen) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return DSA_FAILED;
    }

    signData->size = signLen;

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    return DSA_SUCCESS;
}

int32_t OpensslVerifyDsa(
    const struct HksBlob *plainText, struct HksBlob *signData, struct HksBlob *key, enum HksKeyDigest digestType)
{
    DSA *dsa = InitDsa(key, false);
    if (dsa == NULL) {
        return DSA_FAILED;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        EVP_PKEY_free(pkey);
        return DSA_FAILED;
    }

    EVP_PKEY_assign_DSA(pkey, dsa);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        EVP_MD_CTX_free(mctx);
        return DSA_FAILED;
    }

    const EVP_MD *md = GetOpensslDigestType(digestType);
    if (EVP_DigestVerifyInit(mctx, NULL, md, NULL, pkey) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mctx);
        return DSA_FAILED;
    }

    if (EVP_DigestVerifyUpdate(mctx, plainText->data, plainText->size) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return DSA_FAILED;
    }

    if (EVP_DigestVerifyFinal(mctx, signData->data, signData->size) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return DSA_FAILED;
    }

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    return DSA_SUCCESS;
}

int32_t X509ToDsaPublicKey(struct HksBlob *x509Key, struct HksBlob *publicKey)
{
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, (const unsigned char **)&x509Key->data, x509Key->size);
    if (pkey == NULL) {
        return DSA_FAILED;
    }

    DSA *dsa = EVP_PKEY_get1_DSA(pkey);
    if (dsa == NULL) {
        return DSA_FAILED;
    }
    int32_t ySize = BN_num_bytes(DSA_get0_pub_key(dsa));
    int32_t pSize = BN_num_bytes(DSA_get0_p(dsa));
    int32_t qSize = BN_num_bytes(DSA_get0_q(dsa));
    int32_t gSize = BN_num_bytes(DSA_get0_g(dsa));
    if ((ySize <= 0) || (pSize <= 0) || (qSize <= 0) || (gSize <= 0)) {
        return DSA_FAILED;
    }
    struct KeyMaterialDsa *keyMaterial = (struct KeyMaterialDsa *)publicKey->data;
    keyMaterial->keyAlg = HKS_ALG_DSA;
    keyMaterial->keySize = (ySize + HKS_BITS_PER_BYTE - 1) / HKS_BITS_PER_BYTE * HKS_BITS_PER_BYTE * HKS_BITS_PER_BYTE;
    keyMaterial->xSize = 0;
    keyMaterial->ySize = ySize;
    keyMaterial->pSize = pSize;
    keyMaterial->qSize = qSize;
    keyMaterial->gSize = gSize;

    if ((BN_bn2bin(DSA_get0_pub_key(dsa), publicKey->data + sizeof(struct KeyMaterialDsa) + keyMaterial->xSize) == 0) ||
        (BN_bn2bin(DSA_get0_p(dsa), publicKey->data + sizeof(struct KeyMaterialDsa) + keyMaterial->xSize + ySize) ==
            0) ||
        (BN_bn2bin(DSA_get0_q(dsa),
            publicKey->data + sizeof(struct KeyMaterialDsa) + keyMaterial->xSize + ySize + pSize) == 0) ||
        (BN_bn2bin(DSA_get0_g(dsa),
            publicKey->data + sizeof(struct KeyMaterialDsa) + keyMaterial->xSize + ySize + pSize + qSize) == 0)) {
        free(publicKey->data);
        return DSA_FAILED;
    }

    return DSA_SUCCESS;
}

void DsaGetx509PubKey(EVP_PKEY *pkey, struct HksBlob *x509Key)
{
    uint8_t *tmp = NULL;
    int32_t length = i2d_PUBKEY(pkey, &tmp);
    x509Key->size = length;
    x509Key->data = tmp;
}

int32_t SaveDsaKeyToHksBlob(EVP_PKEY *pkey, const uint32_t keySize, struct HksBlob *key)
{
    int32_t ret;
    uint32_t opensslKeyByteLen = HKS_KEY_BYTES(keySize);
    if (opensslKeyByteLen < OPENSSL_DSA_MIN_KEY_LEN) {
        opensslKeyByteLen = OPENSSL_DSA_MIN_KEY_LEN;
    }
    uint32_t keyByteLen = (opensslKeyByteLen + OPENSSL_KEY_BLOCK - 1) / OPENSSL_KEY_BLOCK * OPENSSL_KEY_BLOCK;

    struct KeyMaterialDsa *keyMaterial = (struct KeyMaterialDsa *)key->data;
    keyMaterial->keyAlg = HKS_ALG_DSA;
    keyMaterial->keySize = keyByteLen * HKS_BITS_PER_BYTE;
    keyMaterial->xSize = (keyByteLen > OPENSSL_DSA_KEY_LEN_DIVID) ? HKS_DIGEST_SHA256_LEN : HKS_DIGEST_SHA1_LEN;
    keyMaterial->ySize = keyByteLen;
    keyMaterial->pSize = keyByteLen;
    keyMaterial->qSize = (keyByteLen > OPENSSL_DSA_KEY_LEN_DIVID) ? HKS_DIGEST_SHA256_LEN : HKS_DIGEST_SHA1_LEN;
    keyMaterial->gSize = keyByteLen;

    const BIGNUM *x = DSA_get0_priv_key(EVP_PKEY_get0_DSA(pkey));
    const BIGNUM *y = DSA_get0_pub_key(EVP_PKEY_get0_DSA(pkey));
    const BIGNUM *p = DSA_get0_p(EVP_PKEY_get0_DSA(pkey));
    const BIGNUM *q = DSA_get0_q(EVP_PKEY_get0_DSA(pkey));
    const BIGNUM *g = DSA_get0_g(EVP_PKEY_get0_DSA(pkey));

    int32_t offset = sizeof(struct KeyMaterialDsa);
    ret = BN_bn2bin(x, key->data + offset + (keyMaterial->xSize - BN_num_bytes(x)));
    if (ret <= 0) {
        return DSA_FAILED;
    }
    offset += keyMaterial->xSize;
    ret = BN_bn2bin(y, key->data + offset + (keyMaterial->ySize - BN_num_bytes(y)));
    if (ret <= 0) {
        return DSA_FAILED;
    }
    offset += keyMaterial->ySize;
    ret = BN_bn2bin(p, key->data + offset + (keyMaterial->pSize - BN_num_bytes(p)));
    if (ret <= 0) {
        return DSA_FAILED;
    }
    offset += keyMaterial->pSize;
    ret = BN_bn2bin(q, key->data + offset + (keyMaterial->qSize - BN_num_bytes(q)));
    if (ret <= 0) {
        return DSA_FAILED;
    }
    offset += keyMaterial->qSize;
    ret = BN_bn2bin(g, key->data + offset + (keyMaterial->gSize - BN_num_bytes(g)));
    if (ret <= 0) {
        return DSA_FAILED;
    }
    return DSA_SUCCESS;
}
