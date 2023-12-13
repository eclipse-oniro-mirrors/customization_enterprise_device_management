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

#ifndef INTERFACES_KITS_USB_MANAGER_INCLUDE_USB_MANAGER_ADDON_H
#define INTERFACES_KITS_USB_MANAGER_INCLUDE_USB_MANAGER_ADDON_H

#include "edm_constants.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "usb_device_id.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncSetUsbPolicyCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    int32_t policy;
};

constexpr int32_t USB_POLICY[] = {
    EdmConstants::STORAGE_USB_POLICY_READ_WRITE,
    EdmConstants::STORAGE_USB_POLICY_READ_ONLY,
    EdmConstants::STORAGE_USB_POLICY_DISABLED
};

class UsbManagerAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value SetUsbPolicy(napi_env env, napi_callback_info info);
    static void CreateUsbPolicyEnum(napi_env env, napi_value value);
    static void NativeSetUsbPolicy(napi_env env, void *data);
    static napi_value DisableUsb(napi_env env, napi_callback_info info);
    static napi_value IsUsbDisabled(napi_env env, napi_callback_info info);
    static napi_value AddAllowedUsbDevices(napi_env env, napi_callback_info info);
    static napi_value RemoveAllowedUsbDevices(napi_env env, napi_callback_info info);
    static napi_value AddOrRemoveAllowedUsbDevices(napi_env env, napi_callback_info info, bool isAdd);
    static bool ParseUsbDevicesArray(napi_env env, std::vector<UsbDeviceId> &usbDeviceIds, napi_value object);
    static bool GetUsbDeviceIdFromNAPI(napi_env env, napi_value value, UsbDeviceId &usbDeviceId);
    static napi_value GetAllowedUsbDevices(napi_env env, napi_callback_info info);
    static napi_value UsbDeviceIdToJsObj(napi_env env, const UsbDeviceId &usbDeviceId);
    static napi_value SetUsbStorageDeviceAccessPolicy(napi_env env, napi_callback_info info);
    static napi_value GetUsbStorageDeviceAccessPolicy(napi_env env, napi_callback_info info);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_USB_MANAGER_INCLUDE_USB_MANAGER_ADDON_H
