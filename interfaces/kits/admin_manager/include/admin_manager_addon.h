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

#ifndef INTERFACES_KITS_ADMIN_MANAGER_INCLUDE_ADMIN_MANAGER_ADDON_H
#define INTERFACES_KITS_ADMIN_MANAGER_INCLUDE_ADMIN_MANAGER_ADDON_H

#include "admin_type.h"
#include "datetime_manager_proxy.h"
#include "edm_errors.h"
#include "element_name.h"
#include "ent_info.h"
#include "enterprise_device_mgr_proxy.h"
#include "ienterprise_device_mgr.h"
#include "managed_event.h"
#include "napi_edm_error.h"
#include "napi_edm_common.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi/native_api.h"
#include "want.h"

namespace OHOS {
namespace EDM {
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

struct AsyncSubscribeManagedEventCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::vector<uint32_t> managedEvent;
    bool subscribe = true;
};

class AdminManager {
public:
    AdminManager();
    ~AdminManager() = default;
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value EnableAdmin(napi_env env, napi_callback_info info);
    static napi_value DisableAdmin(napi_env env, napi_callback_info info);
    static napi_value DisableSuperAdmin(napi_env env, napi_callback_info info);
    static napi_value GetEnterpriseInfo(napi_env env, napi_callback_info info);
    static napi_value SetEnterpriseInfo(napi_env env, napi_callback_info info);
    static napi_value IsSuperAdmin(napi_env env, napi_callback_info info);
    static napi_value isAdminEnabled(napi_env env, napi_callback_info info);
    static napi_value CreateAdminTypeObject(napi_env env);
    static napi_value SubscribeManagedEvent(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeManagedEvent(napi_env env, napi_callback_info info);

    static void NativeEnableAdmin(napi_env env, void *data);
    static void NativeDisableSuperAdmin(napi_env env, void *data);
    static void NativeDisableAdmin(napi_env env, void *data);
    static void NativeGetEnterpriseInfo(napi_env env, void *data);
    static void NativeSetEnterpriseInfo(napi_env env, void *data);
    static void NativeIsSuperAdmin(napi_env env, void *data);
    static void NativeIsAdminEnabled(napi_env env, void *data);
    static void NativeSubscribeManagedEvent(napi_env env, void *data);
    static void NativeGetEnterpriseInfoComplete(napi_env env, napi_status status, void *data);

    static void ConvertEnterpriseInfo(napi_env env, napi_value objEntInfo, EntInfo &entInfo);
    static bool ParseEnterpriseInfo(napi_env env, EntInfo &enterpriseInfo, napi_value args);
    static bool ParseManagedEvent(napi_env env, std::vector<uint32_t> &managedEvent, napi_value args);
    static void CreateAdminTypeObject(napi_env env, napi_value value);
    static void CreateManagedEventObject(napi_env env, napi_value value);
private:
    static bool checkEnableAdminParamType(napi_env env, size_t argc,
        napi_value* argv, bool &hasCallback, bool &hasUserId);
    static bool checkAdminWithUserIdParamType(napi_env env, size_t argc,
        napi_value* argv, bool &hasCallback, bool &hasUserId);
    static napi_value HandleManagedEvent(napi_env env, napi_callback_info info, bool subscribe);
    static std::shared_ptr<EnterpriseDeviceMgrProxy> proxy_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_ADMIN_MANAGER_INCLUDE_ADMIN_MANAGER_ADDON_H
