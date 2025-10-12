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

#include "image_source.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_adapter.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "permission_managed_state_info.h"
#include "pixel_map.h"
#include "security_manager_proxy.h"
#include "want.h"
#include "watermark_param.h"

namespace OHOS {
namespace EDM {
struct AsyncCertCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    CertBlobCA certblobCA;
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
    static napi_value InstallUserCertificateSync(napi_env env, napi_value argv,
        AsyncCertCallbackInfo *asyncCallbackInfo);
    static napi_value InstallUserCertificate(napi_env env, napi_callback_info info);
    static napi_value UninstallUserCertificate(napi_env env, napi_callback_info info);
    static void NativeInstallUserCertificate(napi_env env, void *data);
    static void NativeUninstallUserCertificate(napi_env env, void *data);
    static napi_value GetUserCertificates(napi_env env, napi_callback_info info);
    static bool ParseCertBlob(napi_env env, napi_value object, AsyncCertCallbackInfo *asyncCertCallbackInfo);
    static napi_value SetAppClipboardPolicy(napi_env env, napi_callback_info info);
    static napi_value GetAppClipboardPolicy(napi_env env, napi_callback_info info);
    static void CreatePermissionManagedStateObject(napi_env env, napi_value value);
    static void CreateClipboardPolicyObject(napi_env env, napi_value value);
    static napi_value SetWatermarkImage(napi_env env, napi_callback_info info);
    static napi_value CancelWatermarkImage(napi_env env, napi_callback_info info);
    static std::shared_ptr<Media::PixelMap> Decode(const std::string url);
    static bool GetPixelMapData(std::shared_ptr<Media::PixelMap> pixelMap, std::shared_ptr<WatermarkParam> param);
    static napi_value CheckBuildWatermarkParam(napi_env env, napi_value* argv,
        std::shared_ptr<WatermarkParam> &paramPtr);
    static void SetClipboardPolicyParamHandle(AddonMethodSign &addonMethodSign, int flag);
    static void GetClipboardPolicyParamHandle(AddonMethodSign &addonMethodSign, int flag);
    static napi_value SetPermissionManagedState(napi_env env, napi_callback_info info);
    static napi_value GetPermissionManagedState(napi_env env, napi_callback_info info);
    static bool JsObjToManagedState(napi_env env, napi_value object, ManagedState &managedState);
    static bool JsObjToApplicationInstance(napi_env env, napi_value object, MessageParcel &data);
    static void SetExternalSourceExtensionsPolicy(napi_env env, napi_callback_info info);
    static void GetExternalSourceExtensionsPolicy(napi_env env, napi_callback_info info);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_SECURITY_MANAGER_INCLUDE_SECURITY_MANAGER_ADDON_H
