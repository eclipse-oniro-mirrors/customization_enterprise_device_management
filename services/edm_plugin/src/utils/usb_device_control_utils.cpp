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

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "usb_device_control_ipc.h"
#include "usb_device_info_mapper.h"
#include "usb_flat_device_info.h"

namespace OHOS {
namespace EDM {
namespace {
ErrCode MapUsbRet(int32_t usbRet, const char *apiName)
{
    if (usbRet == static_cast<int32_t>(EdmReturnErrCode::INTERFACE_UNSUPPORTED)) {
        EDMLOGW("UsbDeviceControlUtils %{public}s: USB device-control API unsupported", apiName);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbDeviceControlUtils %{public}s: USB interface not init", apiName);
        return ERR_OK;
    }
    if (usbRet != ERR_OK) {
        EDMLOGE("UsbDeviceControlUtils %{public}s failed, ret=%{public}d", apiName, usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace

ErrCode UsbDeviceControlUtils::GetUsbDeviceInfos(std::vector<UsbDeviceInfo> &infos)
{
    std::vector<UsbFlatDeviceInfo> flatList;
    int32_t usbRet = UsbDeviceControlIpc::GetAllDevices(flatList);
    if (usbRet == static_cast<int32_t>(EdmReturnErrCode::INTERFACE_UNSUPPORTED)) {
        EDMLOGW("UsbDeviceControlUtils::GetUsbDeviceInfos: USB device-control API unsupported");
        infos.clear();
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbDeviceControlUtils::GetUsbDeviceInfos: USB interface not init, empty list");
        infos.clear();
        return ERR_OK;
    }
    if (usbRet != ERR_OK) {
        EDMLOGE("UsbDeviceControlUtils::GetUsbDeviceInfos GetAllDevices failed, ret=%{public}d", usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
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
    uint8_t busNum = static_cast<uint8_t>(config.busNum);
    uint8_t devAddr = static_cast<uint8_t>(config.devAddr);
    if (UsbDeviceInfoMapper::IsInterfaceAuthorize(config)) {
        if (config.configId < 0 || config.interfaceId < 0 ||
            config.configId > static_cast<int32_t>(UINT8_MAX) ||
            config.interfaceId > static_cast<int32_t>(UINT8_MAX)) {
            EDMLOGE("UsbDeviceControlUtils::SetUsbDeviceStates config/interface id out of range");
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
        int32_t usbRet = UsbDeviceControlIpc::UsbInterfaceAuthorize(busNum, devAddr,
            static_cast<uint8_t>(config.configId), static_cast<uint8_t>(config.interfaceId), isEnable);
        return MapUsbRet(usbRet, "UsbInterfaceAuthorize");
    }
    int32_t usbRet = UsbDeviceControlIpc::UsbDeviceAuthorize(busNum, devAddr, isEnable);
    return MapUsbRet(usbRet, "UsbDeviceAuthorize");
}
} // namespace EDM
} // namespace OHOS
