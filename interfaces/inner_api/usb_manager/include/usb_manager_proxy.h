/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#ifdef USB_EDM_ENABLE
#include "usb_interface_type.h"
#endif

namespace OHOS {
namespace EDM {
class UsbManagerProxy {
public:
    static std::shared_ptr<UsbManagerProxy> GetUsbManagerProxy();
    int32_t SetUsbReadOnly(MessageParcel &data);
    int32_t DisableUsb(MessageParcel &data);
    int32_t IsUsbDisabled(MessageParcel &data, bool &result);
    int32_t AddAllowedUsbDevices(MessageParcel &data);
    int32_t RemoveAllowedUsbDevices(MessageParcel &data);
    int32_t GetAllowedUsbDevices(MessageParcel &data, std::vector<UsbDeviceId> &result);
    int32_t SetUsbStorageDeviceAccessPolicy(MessageParcel &data);
    int32_t GetUsbStorageDeviceAccessPolicy(MessageParcel &data, int32_t &result);
#ifdef USB_EDM_ENABLE
    int32_t AddOrRemoveDisallowedUsbDevices(MessageParcel &data, bool isAdd);
    int32_t GetDisallowedUsbDevices(MessageParcel &data,
        std::vector<OHOS::USB::UsbDeviceType> &result);
#endif

private:
    static std::shared_ptr<UsbManagerProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_USB_MANAGER_INCLUDE_USB_MANAGER_PROXY_H
