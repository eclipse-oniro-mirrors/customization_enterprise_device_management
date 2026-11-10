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

#include "usb_device_control_utils.h"

#include <cstdint>

#include "edm_errors.h"
#include "edm_log.h"
#include "usb_device_info_mapper.h"
#include "usb_flat_device_info.h"

namespace OHOS {
namespace EDM {
ErrCode UsbDeviceControlUtils::GetUsbDeviceInfos(std::vector<UsbDeviceInfo> &infos)
{
    // 不在此实现 GetAllDevices：联调时调用 UsbSrvClient::GetAllDevices，填入 flatList 再映射。
    std::vector<UsbFlatDeviceInfo> flatList;
    EDMLOGI("UsbDeviceControlUtils::GetUsbDeviceInfos: USB client not wired, empty list");
    UsbDeviceInfoMapper::ToKitDeviceInfos(flatList, infos);
    return ERR_OK;
}

ErrCode UsbDeviceControlUtils::SetUsbDeviceStates(const USBDeviceConfigInfo &config, bool isEnable)
{
    if (config.busNum < 0 || config.devAddr < 0 ||
        config.busNum > static_cast<int32_t>(UINT8_MAX) ||
        config.devAddr > static_cast<int32_t>(UINT8_MAX)) {
        EDMLOGE("UsbDeviceControlUtils::SetUsbDeviceStates busNum/devAddr out of uint8 range");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    // 不在此实现 Authorize：联调时按维度调用
    // UsbSrvClient::UsbDeviceAuthorize / UsbInterfaceAuthorize。
    if (UsbDeviceInfoMapper::IsInterfaceAuthorize(config)) {
        if (config.configId < 0 || config.interfaceId < 0 ||
            config.configId > static_cast<int32_t>(UINT8_MAX) ||
            config.interfaceId > static_cast<int32_t>(UINT8_MAX)) {
            EDMLOGE("UsbDeviceControlUtils::SetUsbDeviceStates config/interface id out of range");
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
        EDMLOGI("UsbDeviceControlUtils::SetUsbDeviceStates interface path not wired "
            "bus=%{public}d addr=%{public}d cfg=%{public}d iface=%{public}d enable=%{public}d",
            config.busNum, config.devAddr, config.configId, config.interfaceId, isEnable);
        return ERR_OK;
    }
    EDMLOGI("UsbDeviceControlUtils::SetUsbDeviceStates device path not wired "
        "bus=%{public}d addr=%{public}d enable=%{public}d",
        config.busNum, config.devAddr, isEnable);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
