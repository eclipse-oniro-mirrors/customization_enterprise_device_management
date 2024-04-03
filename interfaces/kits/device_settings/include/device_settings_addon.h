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

#ifndef INTERFACES_KITS_DEVICE_SETTINGS_INCLUDE_DEVICE_SETTINGS_ADDON_H
#define INTERFACES_KITS_DEVICE_SETTINGS_INCLUDE_DEVICE_SETTINGS_ADDON_H

#include "device_settings_proxy.h"
#include "edm_errors.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncScreenOffTimeCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    int32_t time = 0;
};

struct AsyncCertCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::vector<uint8_t> certArray;
    std::string alias;
};

class DeviceSettingsAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value SetScreenOffTime(napi_env env, napi_callback_info info);
    static napi_value GetScreenOffTime(napi_env env, napi_callback_info info);
    static napi_value SetPowerPolicy(napi_env env, napi_callback_info info);
    static napi_value GetPowerPolicy(napi_env env, napi_callback_info info);
    static void NativeGetScreenOffTime(napi_env env, void *data);

    static napi_value InstallUserCertificate(napi_env env, napi_callback_info info);
    static napi_value UninstallUserCertificate(napi_env env, napi_callback_info info);
    static void NativeInstallUserCertificate(napi_env env, void *data);
    static void NativeUninstallUserCertificate(napi_env env, void *data);
    static bool ParseCertBlob(napi_env env, napi_value object, AsyncCertCallbackInfo *asyncCertCallbackInfo);
    static bool JsObjToPowerScene(napi_env env, napi_value object, PowerScene &powerScene);
    static bool JsObjToPowerPolicy(napi_env env, napi_value object, PowerPolicy &powerPolicy);
    static void CreatePowerSceneObject(napi_env env, napi_value value);
    static void CreatePowerPolicyActionObject(napi_env env, napi_value value);
    static napi_value ConvertPolicyPolicyToJs(napi_env env, PowerPolicy &powerPolicy);

    static napi_value SetValue(napi_env env, napi_callback_info info);
    static napi_value GetValue(napi_env env, napi_callback_info info);
    static bool JsStrToPowerScene(napi_env env, std::string jsStr, PowerScene &powerScene);
    static bool JsStrToPowerPolicy(napi_env env, std::string jsStr, PowerPolicy &powerPolicy);
    static int32_t ConvertPowerPolicyToJsStr(
        napi_env env, PowerScene &powerScene, PowerPolicy &powerPolicy, std::string &info);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_DEVICE_SETTINGS_INCLUDE_DEVICE_SETTINGS_ADDON_H
