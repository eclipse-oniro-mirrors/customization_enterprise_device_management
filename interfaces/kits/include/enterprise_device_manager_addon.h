/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ENTERPRISE_DEVICE_MGR_ADDON_H
#define ENTERPRISE_DEVICE_MGR_ADDON_H

#include "admin_type.h"
#include "device_settings_manager.h"
#include "edm_errors.h"
#include "element_name.h"
#include "ent_info.h"
#include "enterprise_device_mgr_proxy.h"
#include "ienterprise_device_mgr.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi/native_api.h"
#include "ohos/aafwk/content/want.h"

namespace OHOS {
namespace EDM {
struct AsyncCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback = 0;
    int32_t ret;
    bool boolRet = true;
    int32_t err = 0;
};

struct AsyncActivateAdminCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    EntInfo entInfo;
    int32_t adminType = 0;
};

struct AsyncDeactivateAdminCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
};

struct AsyncDeactivateSuperAdminCallbackInfo : AsyncCallbackInfo {
    std::string bundleName;
};

struct AsyncGetEnterpriseInfoCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    EntInfo entInfo;
};

struct AsyncSetDateTimeCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    int64_t time;
};

struct AsyncSetEnterpriseInfoCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    EntInfo entInfo;
};

struct AsyncIsSuperAdminCallbackInfo : AsyncCallbackInfo {
    std::string bundleName;
};

struct AsyncIsAdminActiveCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
};

struct AsyncGetDeviceSettingsManagerCallbackInfo : AsyncCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback = 0;
};

class EnterpriseDeviceManagerAddon {
public:
    EnterpriseDeviceManagerAddon();
    ~EnterpriseDeviceManagerAddon() = default;
    static thread_local napi_ref g_classDeviceSettingsManager;

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value ActivateAdmin(napi_env env, napi_callback_info info);
    static napi_value DeactivateAdmin(napi_env env, napi_callback_info info);
    static napi_value DeactivateSuperAdmin(napi_env env, napi_callback_info info);
    static napi_value GetEnterpriseInfo(napi_env env, napi_callback_info info);
    static napi_value SetEnterpriseInfo(napi_env env, napi_callback_info info);
    static napi_value IsSuperAdmin(napi_env env, napi_callback_info info);
    static napi_value IsAdminAppActive(napi_env env, napi_callback_info info);
    static napi_value HandleAsyncWork(napi_env env, AsyncCallbackInfo *context, std::string workName,
        napi_async_execute_callback execute, napi_async_complete_callback complete);
    static napi_value CreateAdminTypeObject(napi_env env);
    static std::string GetStringFromNAPI(napi_env env, napi_value value);
    static napi_value GetDeviceSettingsManager(napi_env env, napi_callback_info info);
    static napi_value SetDateTime(napi_env env, napi_callback_info info);

    static void NativeActivateAdmin(napi_env env, void *data);
    static void NativeDeactivateSuperAdmin(napi_env env, void *data);
    static void NativeDeactivateAdmin(napi_env env, void *data);
    static void NativeGetEnterpriseInfo(napi_env env, void *data);
    static void NativeSetEnterpriseInfo(napi_env env, void *data);
    static void NativeIsSuperAdmin(napi_env env, void *data);
    static void NativeIsAdminActive(napi_env env, void *data);
    static void NativeSetDateTime(napi_env env, void *data);

    static void NativeBoolCallbackComplete(napi_env env, napi_status status, void *data);
    static void NativeGetEnterpriseInfoComplete(napi_env env, napi_status status, void *data);

    static void ConvertEnterpriseInfo(napi_env env, napi_value objEntInfo, EntInfo &entInfo);
    static bool ParseEnterpriseInfo(napi_env env, EntInfo &enterpriseInfo, napi_value args);
    static napi_value ParseString(napi_env env, std::string &param, napi_value args);
    static napi_value CreateErrorMessage(napi_env env, std::string msg);
    static bool ParseElementName(napi_env env, OHOS::AppExecFwk::ElementName &elementName, napi_value args);
    static napi_value ParseStringArray(napi_env env, std::vector<std::string> &hapFiles, napi_value args);
    static bool MatchValueType(napi_env env, napi_value value, napi_valuetype targetType);
    static void CreateAdminTypeObject(napi_env env, napi_value value);
    static napi_value CreateUndefined(napi_env env);
    static napi_value ParseInt(napi_env env, int32_t &param, napi_value args);
    static napi_value ParseLong(napi_env env, int64_t &param, napi_value args);

    static napi_value DeviceSettingsManagerConstructor(napi_env env, napi_callback_info info);

private:
    static std::shared_ptr<EnterpriseDeviceMgrProxy> proxy_;
    static std::shared_ptr<DeviceSettingsManager> deviceSettingsManager_;
};
} // namespace EDM
} // namespace OHOS

#endif /* ENTERPRISE_DEVICE_MGR_ADDON_H */
