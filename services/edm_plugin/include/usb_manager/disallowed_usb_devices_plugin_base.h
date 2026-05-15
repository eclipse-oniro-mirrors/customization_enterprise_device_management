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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_USB_DEVICES_PLUGIN_BASE_H
#define SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_USB_DEVICES_PLUGIN_BASE_H

#include "array_usb_device_type_serializer_base.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "usb_interface_type.h"

#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace EDM {
class DisallowedUsbDevicesPluginBase {
public:
    virtual ~DisallowedUsbDevicesPluginBase() = default;

    ErrCode OnSetPolicy(std::vector<USB::UsbDeviceType> &data,
        std::vector<USB::UsbDeviceType> &currentData, std::vector<USB::UsbDeviceType> &mergeData, int32_t userId);
    ErrCode OnRemovePolicy(std::vector<USB::UsbDeviceType> &data,
        std::vector<USB::UsbDeviceType> &currentData, std::vector<USB::UsbDeviceType> &mergeData, int32_t userId);
    ErrCode OnBaseGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId);
    ErrCode OnAdminRemove(const std::string &adminName, std::vector<USB::UsbDeviceType> &data,
        std::vector<USB::UsbDeviceType> &mergeData, int32_t userId);
    void OnOtherServiceStart(int32_t systemAbilityId);

protected:
    virtual const char* GetPolicyName() const = 0;
    virtual uint32_t GetDisallowedUsbDevicesTypeMaxSize() const = 0;
    virtual const char* GetConflictPolicyName() const = 0;
    virtual ErrCode SetDisallowedDevices(std::vector<USB::UsbDeviceType> &data) = 0;
    virtual std::string GetPluginName() const = 0;
    virtual std::shared_ptr<ArrayUsbDeviceTypeSerializerBase> GetSerializer() = 0;

    void CombineDataWithStorageAccessPolicy(std::vector<USB::UsbDeviceType> policyData,
        std::vector<USB::UsbDeviceType> &combineData);
    ErrCode HasConflictPolicy(bool &hasConflict, std::vector<USB::UsbDeviceType> &usbDeviceTypes);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_USB_DEVICES_PLUGIN_BASE_H
