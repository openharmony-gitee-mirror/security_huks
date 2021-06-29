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

#ifndef HKS_FILE_OPERATOR_H
#define HKS_FILE_OPERATOR_H

#include "hks_type.h"

#define HKS_MAX_FILE_NAME_LEN 512

#ifdef _STORAGE_LITE_
#define HKS_KEY_STORE_PATH            "./hks_store/"
#else
#define HKS_KEY_STORE_PATH            "/data/data/maindata"
#define HKS_KEY_STORE_BAK_PATH        "/data/data/bakdata"
#define HKS_KEY_STORE_KEY_PATH        "key"
#define HKS_KEY_STORE_CERTCHAIN_PATH  "certchain"
#define HKS_KEY_STORE_ROOT_KEY_PATH   "info"
#endif

struct HksFileDirentInfo {
    char *fileName; /* point to dirent->d_name */
};

#ifdef __cplusplus
extern "C" {
#endif

uint32_t HksFileRead(const char *path, const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len);

int32_t HksFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len);

int32_t HksFileRemove(const char *path, const char *fileName);

uint32_t HksFileSize(const char *path, const char *fileName);

int32_t HksIsFileExist(const char *path, const char *fileName);

int32_t HksMakeDir(const char *path);

void *HksOpenDir(const char *path);

int32_t HksCloseDir(void *dirp);

int32_t HksGetDirFile(void *dirp, struct HksFileDirentInfo *direntInfo);

int32_t HksRemoveDir(const char *dirPath);

#ifdef __cplusplus
}
#endif

#endif