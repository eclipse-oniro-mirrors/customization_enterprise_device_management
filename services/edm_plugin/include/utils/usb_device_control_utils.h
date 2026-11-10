/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_DEVICE_CONTROL_UTILS_H
#define SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_DEVICE_CONTROL_UTILS_H

#include <vector>

#include "edm_errors.h"
#include "usb_device_info.h"

namespace OHOS {
namespace EDM {
class UsbDeviceControlUtils {
public:
    // EDM 侧入口：参数校验 + 映射；不实现 USB GetAllDevices/Authorize（属 #1458）。
    static ErrCode GetUsbDeviceInfos(std::vector<UsbDeviceInfo> &infos);
    static ErrCode SetUsbDeviceStates(const USBDeviceConfigInfo &config, bool isEnable);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_DEVICE_CONTROL_UTILS_H
