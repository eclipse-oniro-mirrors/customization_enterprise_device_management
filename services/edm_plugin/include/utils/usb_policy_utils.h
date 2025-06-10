/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COMMON_NATIVE_INCLUDE_USB_POLICY_UTILS_H
#define COMMON_NATIVE_INCLUDE_USB_POLICY_UTILS_H

#include "edm_errors.h"
#include "usb_device_id.h"
#include "usb_interface_type.h"

namespace OHOS {
namespace EDM {
class UsbPolicyUtils {
public:
    static ErrCode SetUsbDisabled(bool data);
    static ErrCode AddAllowedUsbDevices(std::vector<UsbDeviceId> data);
    static ErrCode SetDisallowedUsbDevices(std::vector<USB::UsbDeviceType> data);
    static ErrCode QueryAllCreatedOsAccountIds(std::vector<int32_t> &userIds);
#ifdef FEATURE_PC_ONLY
    static ErrCode IsUsbStorageDeviceWriteDisallowed(bool &isDisallowed);
#endif
};
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_USB_POLICY_UTILS_H