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

#include "usb_policy_utils.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "usb_device.h"
#include "usb_srv_client.h"

namespace OHOS {
namespace EDM {
ErrCode UsbPolicyUtils::SetUsbDisabled(bool data)
{
    EDMLOGI("UsbPolicyUtils SetUsbDisabled...disable = %{public}d", data);
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    int32_t usbRet = srvClient.ManageGlobalInterface(data);
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbPolicyUtils ManageGlobalInterface failed! USB interface not init!");
    }
    if (usbRet != ERR_OK && usbRet != EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGE("UsbPolicyUtils ManageGlobalInterface failed! ret: %{public}d", usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode UsbPolicyUtils::AddAllowedUsbDevices(std::vector<UsbDeviceId> data)
{
    EDMLOGI("UsbPolicyUtils AddAllowedUsbDevices....data size = %{public}zu", data.size());
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    std::vector<OHOS::USB::UsbDevice> allDevices;
    int32_t getRet = srvClient.GetDevices(allDevices);
    if (getRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbPolicyUtils getDevices failed! USB interface not init!");
    }
    if (getRet != ERR_OK && getRet != EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGE("UsbPolicyUtils getDevices failed: %{public}d", getRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("UsbPolicyUtils AddAllowedUsbDevices getDevices size: %{public}zu", allDevices.size());
    for (const auto &item : allDevices) {
        bool isAllowed = (std::find_if(data.begin(), data.end(), [item](UsbDeviceId trustItem) {
            return item.GetVendorId() == trustItem.GetVendorId() && item.GetProductId() == trustItem.GetProductId();
        }) != data.end());
        if (srvClient.ManageDevice(item.GetVendorId(), item.GetProductId(), !isAllowed) != ERR_OK) {
            EDMLOGW("UsbPolicyUtils ManageDevice: vid:%{public}d pid:%{public}d, %{public}d failed!",
                item.GetVendorId(), item.GetProductId(), isAllowed);
        }
    }
    return ERR_OK;
}

ErrCode UsbPolicyUtils::SetDisallowedUsbDevices(std::vector<USB::UsbDeviceType> data)
{
    EDMLOGI("UsbPolicyUtils SetDisallowedUsbDevices...data size = %{public}zu", data.size());
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    int32_t usbRet = srvClient.ManageInterfaceType(data, true);
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbPolicyUtils ManageInterfaceType failed! USB interface not init!");
    }
    if (usbRet != ERR_OK && usbRet != EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGE("UsbPolicyUtils ManageInterfaceType failed! ret:%{public}d", usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS