/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_DATETIME_MANAGER_INCLUDE_DEVICE_INFO_ADDON_H
#define INTERFACES_KITS_DATETIME_MANAGER_INCLUDE_DEVICE_INFO_ADDON_H

#include "device_info_proxy.h"
#include "edm_errors.h"
#include "napi_edm_adapter.h"
#include "napi_edm_error.h"
#include "napi_edm_common.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi/native_api.h"
#include "patch_info.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncGetDeviceInfoCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
};

class DeviceInfoAddon {
public:
    DeviceInfoAddon();
    ~DeviceInfoAddon() = default;

    static napi_value Init(napi_env env, napi_value exports);
private:
    static napi_value GetDatetimeManagerProxy(napi_env env, napi_callback_info info);
    static napi_value GetDeviceSerial(napi_env env, napi_callback_info info);
    static napi_value GetDisplayVersion(napi_env env, napi_callback_info info);
    static napi_value GetDeviceName(napi_env env, napi_callback_info info);
    static napi_value GetDeviceInfoSync(napi_env env, napi_callback_info info);
    static napi_value GetDeviceInfo(napi_env env, napi_callback_info info, int code);
    static void NativeGetDeviceInfo(napi_env env, void *data);
    static napi_value GetPatchInfo(napi_env env, napi_callback_info info);
    static void NativeGetPatchInfo(napi_env env, void *data);
    static void NativeGetPatchInfoComplete(napi_env env, napi_status status, void *data);
    static napi_value PatchInfoToJsObj(napi_env env, const PatchInfo &patchInfo);
    static napi_value PatchDescriptionToJsObj(napi_env env, const PatchDescription &description);
    static napi_value PatchDescriptionBodyToJsObj(napi_env env, const PatchDescriptionBody &body);
    static napi_value BuildPatchInfoArray(napi_env env, MessageParcel &reply);
};
} // namespace EDM
} // namespace OHOS


#endif // INTERFACES_KITS_DATETIME_MANAGER_INCLUDE_DEVICE_INFO_ADDON_H
