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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_USB_DEVICES_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_USB_DEVICES_PLUGIN_H

#include "plugin_singleton.h"
#include "usb_interface_type.h"

namespace OHOS {
namespace EDM {
class DisallowedUsbDevicesPlugin : public IPlugin {
public:
    DisallowedUsbDevicesPlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override{};
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData, int32_t userId) override;
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData, int32_t userId) override{};
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

private:
    bool HasConflictPolicy(const FuncOperateType type);
    bool CombinePolicyDataAndBeforeData(const FuncOperateType type, std::vector<USB::UsbDeviceType> policyDevices,
        std::vector<USB::UsbDeviceType> beforeDevices, std::vector<USB::UsbDeviceType> &mergeDevices);
    void CombineDataWithStorageAccessPolicy(std::vector<USB::UsbDeviceType> policyData,
        std::vector<USB::UsbDeviceType> &combineData);
    ErrCode EnableAllUsb();
    ErrCode DealDisallowedDevices(std::vector<USB::UsbDeviceType> data);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_USB_DEVICES_PLUGIN_H