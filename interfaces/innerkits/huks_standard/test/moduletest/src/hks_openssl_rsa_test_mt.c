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

#include <stdio.h>

#include "securec.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "hks_crypto_hal.h"
#include "hks_type.h"

void SaveRsaKeyToHksBlob(EVP_PKEY *pkey, const uint32_t keySize, struct HksBlob *key)
{
    const uint32_t keyByteLen = keySize / BIT_NUM_OF_UINT8;

    struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)key->data;
    keyMaterial->keyAlg = HKS_ALG_RSA;
    keyMaterial->keySize = keySize;
    keyMaterial->nSize = keyByteLen;
    keyMaterial->eSize = keyByteLen;
    keyMaterial->dSize = keyByteLen;

    int dataLen;
    uint8_t tmpBuff[keyByteLen];
    memset_s(tmpBuff, keyByteLen, 0x00, keyByteLen);

    uint32_t offset = sizeof(*keyMaterial);
    dataLen = BN_bn2bin(RSA_get0_n(EVP_PKEY_get0_RSA(pkey)), tmpBuff);
    if (dataLen > 0) {
        (void)memcpy_s(key->data + offset + keyByteLen - dataLen, keyMaterial->nSize, tmpBuff, dataLen);
    }

    offset += keyMaterial->nSize;
    dataLen = BN_bn2bin(RSA_get0_e(EVP_PKEY_get0_RSA(pkey)), tmpBuff);
    if (dataLen > 0) {
        (void)memcpy_s(key->data + offset + keyByteLen - dataLen, keyMaterial->eSize, tmpBuff, dataLen);
    }

    offset += keyMaterial->eSize;
    dataLen = BN_bn2bin(RSA_get0_d(EVP_PKEY_get0_RSA(pkey)), tmpBuff);
    if (dataLen > 0) {
        (void)memcpy_s(key->data + offset + keyByteLen - dataLen, keyMaterial->dSize, tmpBuff, dataLen);
    }
}

EVP_PKEY *GenerateRSAKey(const uint32_t keySize)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        return NULL;
    }
    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    if (bne == NULL) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    RSA_generate_key_ex(rsa, keySize, bne, NULL);
    BN_free(bne);

    EVP_PKEY_assign_RSA(pkey, rsa);

    return pkey;
}

void OpensslGetx509PubKey(EVP_PKEY *pkey, struct HksBlob *x509Key)
{
    uint8_t *tmp = NULL;
    int32_t length = i2d_PUBKEY(pkey, &tmp);
    x509Key->size = length;
    x509Key->data = tmp;
}

int32_t X509ToRsaPublicKey(struct HksBlob *x509Key, struct HksBlob *publicKey)
{
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, (const unsigned char **)&x509Key->data, x509Key->size);
    if (pkey == NULL) {
        return RSA_FAILED;
    }
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        return RSA_FAILED;
    }

    int32_t nSize = BN_num_bytes(RSA_get0_n(rsa));
    int32_t eSize = BN_num_bytes(RSA_get0_e(rsa));
    if ((nSize <= 0) || (eSize <= 0)) {
        return RSA_FAILED;
    }

    struct HksPubKeyInfo *pubKeyInfo = (struct HksPubKeyInfo *)publicKey->data;
    pubKeyInfo->keyAlg = HKS_ALG_RSA;
    pubKeyInfo->keySize = RSA_size(rsa) * BIT_NUM_OF_UINT8;
    pubKeyInfo->nOrXSize = nSize;
    pubKeyInfo->eOrYSize = eSize;
    if ((BN_bn2bin(RSA_get0_n(rsa), publicKey->data + sizeof(struct HksPubKeyInfo)) == 0) ||
        (BN_bn2bin(RSA_get0_e(rsa), publicKey->data + sizeof(struct HksPubKeyInfo) + nSize) == 0)) {
        free(publicKey->data);
        return RSA_FAILED;
    }

    return RSA_SUCCESS;
}

static RSA *InitRsa(struct HksBlob *key, const bool needPrivateExponent)
{
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);
    uint8_t buff[HKS_KEY_BYTES(keyMaterial->keySize)];

    uint32_t offset = sizeof(*keyMaterial);
    if (memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->nSize) != 0) {
        return NULL;
    }

    BIGNUM *n = BN_bin2bn(buff, keyMaterial->nSize, NULL);
    offset += keyMaterial->nSize;
    if (memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->eSize) != 0) {
        return NULL;
    }

    BIGNUM *e = BN_bin2bn(buff, keyMaterial->eSize, NULL);
    offset += keyMaterial->eSize;
    BIGNUM *d = NULL;
    if (needPrivateExponent) {
        (void)memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->dSize);

        d = BN_bin2bn(buff, keyMaterial->dSize, NULL);
    }

    RSA *rsa = RSA_new();
    int32_t ret = RSA_set0_key(rsa, n, e, d);
    if (ret != 1) {
        return NULL;
    }

    return rsa;
}

static const EVP_MD *GetOpensslDigestType(enum HksKeyDigest digestType)
{
    switch (digestType) {
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
int32_t EncryptRSA(const struct HksBlob *inData, struct HksBlob *outData, struct HksBlob *key, int padding,
    enum HksKeyDigest digestType)
{
    RSA *rsa = InitRsa(key, false);
    if (rsa == NULL) {
        return RSA_FAILED;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    EVP_PKEY_assign_RSA(pkey, rsa);
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ectx == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    EVP_PKEY_encrypt_init(ectx);

    EVP_PKEY_CTX_set_rsa_padding(ectx, padding);

    if (padding == RSA_PKCS1_OAEP_PADDING) {
        const EVP_MD *md = GetOpensslDigestType(digestType);
        if ((md == NULL) || (EVP_PKEY_CTX_set_rsa_oaep_md(ectx, md) <= 0) ||
            (EVP_PKEY_CTX_set_rsa_mgf1_md(ectx, md) <= 0)) {
            EVP_PKEY_CTX_free(ectx);
            EVP_PKEY_free(pkey);
            return RSA_FAILED;
        }
    }
    size_t outLen = outData->size;
    int result = EVP_PKEY_encrypt(ectx, outData->data, &outLen, inData->data, inData->size);
    if (result != 1) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    outData->size = outLen;

    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_free(pkey);

    return RSA_SUCCESS;
}

int32_t DecryptRSA(const struct HksBlob *inData, struct HksBlob *outData, struct HksBlob *key, int padding,
    enum HksKeyDigest digestType)
{
    RSA *rsa = InitRsa(key, true);
    if (rsa == NULL) {
        return RSA_FAILED;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    EVP_PKEY_assign_RSA(pkey, rsa);
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ectx == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    EVP_PKEY_decrypt_init(ectx);

    EVP_PKEY_CTX_set_rsa_padding(ectx, padding);

    if (padding == RSA_PKCS1_OAEP_PADDING) {
        const EVP_MD *md = GetOpensslDigestType(digestType);
        if ((md == NULL) || (EVP_PKEY_CTX_set_rsa_oaep_md(ectx, md) <= 0) ||
            (EVP_PKEY_CTX_set_rsa_mgf1_md(ectx, md) <= 0)) {
            EVP_PKEY_CTX_free(ectx);
            EVP_PKEY_free(pkey);
            return RSA_FAILED;
        }
    }
    size_t outLen = outData->size;
    int result = EVP_PKEY_decrypt(ectx, outData->data, &outLen, inData->data, inData->size);
    if (result != 1) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    outData->size = outLen;

    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_free(pkey);

    return RSA_SUCCESS;
}
