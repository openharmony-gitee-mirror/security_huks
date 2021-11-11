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

#include "hks_openssl_dh_mt_test.h"

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "hks_crypto_hal.h"
#include "hks_mem.h"

static int32_t DhGetNid(uint32_t keySize, int *nid)
{
    switch (keySize) {
        case HKS_DH_KEY_SIZE_2048:
            *nid = NID_ffdhe2048;
            return DH_SUCCESS;
        case HKS_DH_KEY_SIZE_3072:
            *nid = NID_ffdhe3072;
            return DH_SUCCESS;
        case HKS_DH_KEY_SIZE_4096:
            *nid = NID_ffdhe4096;
            return DH_SUCCESS;
        default:
            return DH_FAILED;
    }
}

static int32_t DhSaveKeyMaterial(const DH *dh, const uint32_t keySize, struct HksBlob *key)
{
    const BIGNUM *pubKey = NULL;
    const BIGNUM *privKey = NULL;
    DH_get0_key(dh, &pubKey, &privKey);
    const uint32_t rawMaterialLen = sizeof(struct KeyMaterialDh) + BN_num_bytes(pubKey) + BN_num_bytes(privKey);
    uint8_t *rawMaterial = (uint8_t *)malloc(rawMaterialLen);
    if (rawMaterial == NULL) {
        return DH_FAILED;
    }

    struct KeyMaterialDh *keyMaterial = (struct KeyMaterialDh *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_DH;
    keyMaterial->keySize = keySize;
    keyMaterial->pubKeySize = BN_num_bytes(pubKey);
    keyMaterial->priKeySize = BN_num_bytes(privKey);
    keyMaterial->reserved = 0;

    uint32_t offset = sizeof(struct KeyMaterialDh);
    BN_bn2bin(pubKey, rawMaterial + offset);
    offset += keyMaterial->pubKeySize;
    BN_bn2bin(privKey, rawMaterial + offset);
    offset += keyMaterial->priKeySize;

    key->size = rawMaterialLen;
    key->data = rawMaterial;

    return DH_SUCCESS;
}

int32_t DhGenerateKey(const int keyLen, struct HksBlob *key)
{
    int32_t ret;
    int nid = 0;
    ret = DhGetNid(keyLen, &nid);
    if (ret != DH_SUCCESS) {
        return ret;
    }

    DH *dh = DH_new_by_nid(nid);
    if (dh == NULL) {
        return DH_FAILED;
    }
    if (DH_generate_key(dh) != 1) {
        DH_free(dh);
        return DH_FAILED;
    }

    ret = DhSaveKeyMaterial(dh, keyLen, key);

    DH_free(dh);

    return ret;
}

static DH *InitDhStruct(const struct HksBlob *key, const bool needPrivateExponent)
{
    int32_t ret = DH_SUCCESS;
    const struct KeyMaterialDh *keyMaterial = (struct KeyMaterialDh *)(key->data);
    if (key->size != sizeof(struct KeyMaterialDh) + keyMaterial->pubKeySize + keyMaterial->priKeySize) {
        return NULL;
    }

    int nid = 0;
    ret = DhGetNid(keyMaterial->keySize, &nid);
    if (ret != DH_SUCCESS) {
        return NULL;
    }

    DH *dh = DH_new_by_nid(nid);
    if (dh == NULL) {
        return NULL;
    }

    uint32_t offset = sizeof(struct KeyMaterialDh);
    BIGNUM *pubKey = BN_bin2bn(key->data + offset, keyMaterial->pubKeySize, NULL);
    offset += keyMaterial->pubKeySize;
    BIGNUM *privKey = BN_bin2bn(key->data + offset, keyMaterial->priKeySize, NULL);

    if (DH_set0_key(dh, pubKey, privKey) != 1) {
        DH_free(dh);
        return NULL;
    }

    return dh;
}

int32_t DhAgreeKey(
    const int keyLen, const struct HksBlob *nativeKey, const struct HksBlob *pubKey, struct HksBlob *sharedKey)
{
    int32_t ret;
    if ((uint32_t)HKS_KEY_BYTES(keyLen) > sharedKey->size) {
        return DH_FAILED;
    }

    struct KeyMaterialDh *pubKeyMaterial = (struct KeyMaterialDh *)pubKey->data;
    BIGNUM *pub = BN_bin2bn(pubKey->data + sizeof(struct KeyMaterialDh), pubKeyMaterial->pubKeySize, NULL);
    if (pub == NULL) {
        return DH_FAILED;
    }

    DH *dh = InitDhStruct(nativeKey, true);
    if (dh == NULL) {
        BN_free(pub);
        return DH_FAILED;
    }

    uint8_t computeKey[DH_size(dh)];

    if (DH_compute_key_padded(computeKey, pub, dh) <= 0) {
        BN_free(pub);
        DH_free(dh);
        return DH_FAILED;
    }

    if (HKS_KEY_BYTES(keyLen) > DH_size(dh)) {
        ret = DH_FAILED;
    } else {
        (void)memcpy_s(sharedKey->data, sharedKey->size, computeKey, HKS_KEY_BYTES(keyLen));
        sharedKey->size = DH_size(dh);
        ret = DH_SUCCESS;
    }

    BN_free(pub);
    DH_free(dh);
    return ret;
}

int32_t DhGetDhPubKey(const struct HksBlob *input, struct HksBlob *output)
{
    struct KeyMaterialDh *keyMaterial = (struct KeyMaterialDh *)input->data;
    if (input->size < sizeof(struct KeyMaterialDh) + keyMaterial->pubKeySize) {
        return DH_FAILED;
    }
    if (output->size < sizeof(struct KeyMaterialDh) + keyMaterial->pubKeySize) {
        return DH_FAILED;
    }

    (void)memcpy_s(output->data, output->size, input->data, sizeof(struct KeyMaterialDh) + keyMaterial->pubKeySize);
    ((struct KeyMaterialDh *)output->data)->priKeySize = 0;
    ((struct KeyMaterialDh *)output->data)->reserved = 0;
    output->size = sizeof(struct KeyMaterialDh) + keyMaterial->pubKeySize;

    return DH_SUCCESS;
}

int32_t DhX509ToHksBlob(const struct HksBlob *x509Key, struct HksBlob *publicKey)
{
    if (x509Key == NULL || x509Key->data == NULL || x509Key->size == 0 || publicKey == NULL) {
        return DH_FAILED;
    }

    uint8_t *data = x509Key->data;

    EVP_PKEY *pkey = d2i_PUBKEY(NULL, (const unsigned char **)&data, x509Key->size);
    if (pkey == NULL) {
        return DH_FAILED;
    }

    DH *dh = EVP_PKEY_get0_DH(pkey);
    if (dh == NULL) {
        return DH_FAILED;
    }

    const BIGNUM *pubKey = DH_get0_pub_key(dh);
    uint32_t dhpubKeySize = BN_num_bytes(pubKey);

    uint8_t *keyBuffer = HksMalloc(sizeof(struct KeyMaterialDh) + dhpubKeySize);
    if (keyBuffer == NULL) {
        return DH_FAILED;
    }
    struct KeyMaterialDh *keyMaterial = (struct KeyMaterialDh *)keyBuffer;
    keyMaterial->keyAlg = HKS_ALG_DH;
    keyMaterial->keySize = DH_bits(dh);
    keyMaterial->pubKeySize = dhpubKeySize;
    keyMaterial->priKeySize = 0;
    keyMaterial->reserved = 0;

    BN_bn2bin(pubKey, keyBuffer + sizeof(struct KeyMaterialDh));

    publicKey->size = dhpubKeySize;
    publicKey->data = keyBuffer;

    SELF_FREE_PTR(pkey, EVP_PKEY_free);
    return DH_SUCCESS;
}

int32_t DhHksBlobToX509(const struct HksBlob *key, struct HksBlob *x509Key)
{
    struct KeyMaterialDh *pubKeyMaterial = (struct KeyMaterialDh *)key->data;
    BIGNUM *pub = BN_bin2bn(key->data + sizeof(struct KeyMaterialDh), pubKeyMaterial->pubKeySize, NULL);
    if (pub == NULL) {
        return DH_FAILED;
    }

    DH *dh = InitDhStruct(key, true);
    if (dh == NULL) {
        BN_free(pub);
        return DH_FAILED;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        DH_free(dh);
        return DH_FAILED;
    }

    if (EVP_PKEY_assign_DH(pkey, dh) <= 0) {
        DH_free(dh);
        EVP_PKEY_free(pkey);
        return DH_FAILED;
    }

    uint8_t *tmp = NULL;
    int32_t length = i2d_PUBKEY(pkey, &tmp);
    x509Key->size = length;
    x509Key->data = tmp;
    return DH_SUCCESS;
}