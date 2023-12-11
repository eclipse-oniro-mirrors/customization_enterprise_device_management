/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_USB_MANAGER_INCLUDE_USB_MANAGER_PROXY_H
#define INTERFACES_INNER_API_USB_MANAGER_INCLUDE_USB_MANAGER_PROXY_H

#include "enterprise_device_mgr_proxy.h"
#include "usb_device_id.h"

namespace OHOS {
namespace EDM {
class UsbManagerProxy {
public:
    static std::shared_ptr<UsbManagerProxy> GetUsbManagerProxy();
    int32_t SetUsbReadOnly(const AppExecFwk::ElementName &admin, bool readOnly);
    int32_t DisableUsb(const AppExecFwk::ElementName &admin, bool disable);
    int32_t IsUsbDisabled(const AppExecFwk::ElementName *admin, bool &result);
    int32_t AddAllowedUsbDevices(const AppExecFwk::ElementName &admin, std::vector<UsbDeviceId> usbDeviceIds);
    int32_t RemoveAllowedUsbDevices(const AppExecFwk::ElementName &admin, std::vector<UsbDeviceId> usbDeviceIds);
    int32_t GetAllowedUsbDevices(const AppExecFwk::ElementName &admin, std::vector<UsbDeviceId> &result);
    int32_t SetUsbStorageDeviceAccessPolicy(const AppExecFwk::ElementName &admin, int32_t usbPolicy);
    int32_t GetUsbStorageDeviceAccessPolicy(const AppExecFwk::ElementName &admin, int32_t &result);

private:
    static std::shared_ptr<UsbManagerProxy> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_USB_MANAGER_INCLUDE_USB_MANAGER_PROXY_H
