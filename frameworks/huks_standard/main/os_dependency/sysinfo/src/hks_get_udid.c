/*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
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

#include "hks_get_udid.h"

#include "securec.h"

#include "hks_log.h"
#include "hks_type.h"

#define HKS_HARDWARE_UDID_LEN 32

#ifndef _CUT_AUTHENTICATE_
#if defined(HKS_SUPPORT_PRODUCT_GT_WATCH)
extern uint8_t GetUdid(uint8_t *buf, uint8_t length);

int32_t HksGetHardwareUdid(uint8_t *udid, uint32_t udidLen)
{
    uint8_t hardwareUdid[HKS_HARDWARE_UDID_LEN] = {0};
    uint8_t resultLen = GetUdid(hardwareUdid, HKS_HARDWARE_UDID_LEN);
    if (resultLen != HKS_HARDWARE_UDID_LEN) {
        HKS_LOG_E("Get Udid failed!");
        return HKS_FAILURE;
    }

    if (memcpy_s(udid, udidLen, hardwareUdid, HKS_HARDWARE_UDID_LEN) != EOK) {
        HKS_LOG_E("Memcpy udid failed!");
        return HKS_ERROR_BAD_STATE;
    }

    return HKS_SUCCESS;
}

#else
int32_t HksGetHardwareUdid(uint8_t *udid, uint32_t udidLen)
{
    const uint8_t testUdid[HKS_HARDWARE_UDID_LEN] = {
        0xFE, 0xF1, 0xFA, 0xD5, 0xB6, 0x9D, 0x4A, 0xC8,
        0x52, 0xE7, 0xF5, 0xA3, 0x8F, 0x0D, 0xE1, 0xC0,
        0x87, 0xA4, 0x40, 0xF2, 0x10, 0x5A, 0xC9, 0x31,
        0xC4, 0xD7, 0x2E, 0xDE, 0x51, 0xE3, 0x73, 0x11,
    };

    if (memcpy_s(udid, udidLen, testUdid, HKS_HARDWARE_UDID_LEN) != EOK) {
        HKS_LOG_E("Memcpy udid failed!");
        return HKS_ERROR_BAD_STATE;
    }

    return HKS_SUCCESS;
}
#endif

#endif /* _CUT_AUTHENTICATE_ */
