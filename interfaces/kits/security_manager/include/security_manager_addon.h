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

#ifndef INTERFACES_KITS_SECURITY_MANAGER_INCLUDE_SECURITY_MANAGER_ADDON_H
#define INTERFACES_KITS_SECURITY_MANAGER_INCLUDE_SECURITY_MANAGER_ADDON_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "security_manager_proxy.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncCertCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::vector<uint8_t> certArray;
    std::string alias;
};

class SecurityManagerAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value GetSecurityPatchTag(napi_env env, napi_callback_info info);
    static napi_value GetDeviceEncryptionStatus(napi_env env, napi_callback_info info);
    static napi_value ConvertDeviceEncryptionStatus(napi_env env, DeviceEncryptionStatus &deviceEncryptionStatus);
    static napi_value SetPasswordPolicy(napi_env env, napi_callback_info info);
    static napi_value GetPasswordPolicy(napi_env env, napi_callback_info info);
    static napi_value GetSecurityStatus(napi_env env, napi_callback_info info);
    static int32_t ConvertDeviceEncryptionToJson(napi_env env, DeviceEncryptionStatus &deviceEncryptionStatus,
        std::string &stringRet);
    static napi_value InstallUserCertificate(napi_env env, napi_callback_info info);
    static napi_value UninstallUserCertificate(napi_env env, napi_callback_info info);
    static void NativeInstallUserCertificate(napi_env env, void *data);
    static void NativeUninstallUserCertificate(napi_env env, void *data);
    static bool ParseCertBlob(napi_env env, napi_value object, AsyncCertCallbackInfo *asyncCertCallbackInfo);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_SECURITY_MANAGER_INCLUDE_SECURITY_MANAGER_ADDON_H
