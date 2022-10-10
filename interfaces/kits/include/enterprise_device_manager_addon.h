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

#ifndef INTERFACES_KITS_INCLUDE_ENTERPRISE_DEVICE_MANAGER_ADDON_H
#define INTERFACES_KITS_INCLUDE_ENTERPRISE_DEVICE_MANAGER_ADDON_H

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
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback = 0;
    ErrCode ret;
    bool boolRet = true;
    int32_t err = 0;
    uint32_t errCode = 0;
    std::string errMessage;
};

struct AsyncEnableAdminCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    EntInfo entInfo;
    int32_t adminType = 0;
    int32_t userId = 0;
};

struct AsyncDisableAdminCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    int32_t userId = 0;
};

struct AsyncDisableSuperAdminCallbackInfo : AsyncCallbackInfo {
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

struct AsyncIsAdminEnabledCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    int32_t userId = 0;
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
    static napi_value EnableAdmin(napi_env env, napi_callback_info info);
    static napi_value DisableAdmin(napi_env env, napi_callback_info info);
    static napi_value DisableSuperAdmin(napi_env env, napi_callback_info info);
    static napi_value GetEnterpriseInfo(napi_env env, napi_callback_info info);
    static napi_value SetEnterpriseInfo(napi_env env, napi_callback_info info);
    static napi_value IsSuperAdmin(napi_env env, napi_callback_info info);
    static napi_value isAdminEnabled(napi_env env, napi_callback_info info);
    static napi_value HandleAsyncWork(napi_env env, AsyncCallbackInfo *context, std::string workName,
        napi_async_execute_callback execute, napi_async_complete_callback complete);
    static napi_value CreateAdminTypeObject(napi_env env);
    static bool GetStringFromNAPI(napi_env env, napi_value value, std::string &resultStr);
    static napi_value GetDeviceSettingsManager(napi_env env, napi_callback_info info);
    static napi_value SetDateTime(napi_env env, napi_callback_info info);

    static void NativeEnableAdmin(napi_env env, void *data);
    static void NativeDisableSuperAdmin(napi_env env, void *data);
    static void NativeDisableAdmin(napi_env env, void *data);
    static void NativeGetEnterpriseInfo(napi_env env, void *data);
    static void NativeSetEnterpriseInfo(napi_env env, void *data);
    static void NativeIsSuperAdmin(napi_env env, void *data);
    static void NativeIsAdminEnabled(napi_env env, void *data);
    static void NativeSetDateTime(napi_env env, void *data);

    static void NativeVoidCallbackComplete(napi_env env, napi_status status, void *data);
    static void NativeBoolCallbackComplete(napi_env env, napi_status status, void *data);
    static void NativeGetEnterpriseInfoComplete(napi_env env, napi_status status, void *data);

    static void ConvertEnterpriseInfo(napi_env env, napi_value objEntInfo, EntInfo &entInfo);
    static bool ParseEnterpriseInfo(napi_env env, EntInfo &enterpriseInfo, napi_value args);
    static bool ParseString(napi_env env, std::string &param, napi_value args);
    static bool ParseElementName(napi_env env, OHOS::AppExecFwk::ElementName &elementName, napi_value args);
    static bool MatchValueType(napi_env env, napi_value value, napi_valuetype targetType);
    static void CreateAdminTypeObject(napi_env env, napi_value value);
    static bool ParseInt(napi_env env, int32_t &param, napi_value args);
    static bool ParseLong(napi_env env, int64_t &param, napi_value args);

    static napi_value DeviceSettingsManagerConstructor(napi_env env, napi_callback_info info);
private:
    static napi_value CreateError(napi_env env, ErrCode errorCode);
    static napi_value CreateError(napi_env env, int32_t errorCode, const std::string &errMessage);
    static std::pair<int32_t, std::string> GetMessageFromReturncode(ErrCode returnCode);
    static bool checkEnableAdminParamType(napi_env env, size_t argc,
        napi_value* argv, bool &hasCallback, bool &hasUserId);
    static bool checkAdminWithUserIdParamType(napi_env env, size_t argc,
        napi_value* argv, bool &hasCallback, bool &hasUserId);
    #define ASSERT_AND_THROW_PARAM_ERROR(env, assertion, message)               \
        do {                                                                       \
            if (!(assertion)) {                                                    \
                napi_throw((env), CreateError((env), (EdmReturnErrCode::PARAM_ERROR), (message)));          \
                napi_value ret = nullptr;                                      \
                return ret;                                                    \
            }                                                                    \
        } while (0)
    static std::map<int32_t, std::string> errMessageMap;
    static std::shared_ptr<EnterpriseDeviceMgrProxy> proxy_;
    static std::shared_ptr<DeviceSettingsManager> deviceSettingsManager_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_INCLUDE_ENTERPRISE_DEVICE_MANAGER_ADDON_H
