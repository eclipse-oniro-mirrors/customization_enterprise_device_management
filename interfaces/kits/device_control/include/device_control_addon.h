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

#ifndef INTERFACES_KITS_DEVICE_CONTROL_INCLUDE_DEVICE_CONTROL_ADDON_H
#define INTERFACES_KITS_DEVICE_CONTROL_INCLUDE_DEVICE_CONTROL_ADDON_H

#include "device_control_proxy.h"
#include "enterprise_device_mgr_proxy.h"
#include "ienterprise_device_mgr.h"
#include "napi_edm_error.h"
#include "napi_edm_common.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi/native_api.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncDeviceControlCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
};

class DeviceControlAddon {
public:
    DeviceControlAddon();
    ~DeviceControlAddon() = default;

    static napi_value Init(napi_env env, napi_value exports);
private:
    static napi_value ResetFactory(napi_env env, napi_callback_info info);
    static napi_value Shutdown(napi_env env, napi_callback_info info);
    static napi_value Reboot(napi_env env, napi_callback_info info);
    static napi_value LockScreen(napi_env env, napi_callback_info info);
    static napi_value OperateDevice(napi_env env, napi_callback_info info);
    static void NativeResetFactory(napi_env env, void *data);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_DATETIME_MANAGER_INCLUDE_DEVICE_INFO_ADDON_H