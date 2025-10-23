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

#ifndef INTERFACES_KITS_APPLICATION_MANAGER_INCLUDE_APPLICATION__MANAGER_ADDON_H
#define INTERFACES_KITS_APPLICATION_MANAGER_INCLUDE_APPLICATION__MANAGER_ADDON_H

#include "application_manager_proxy.h"
#include "edm_errors.h"
#include "napi_edm_error.h"
#include "napi_edm_common.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi/native_api.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncDisallowedRunningBundlesCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::vector<std::string> appIds;
    int32_t userId = 0;
};

class ApplicationManagerAddon {
public:
    ApplicationManagerAddon();
    ~ApplicationManagerAddon() = default;

    static napi_value Init(napi_env env, napi_value exports);

    static napi_value AddDisallowedRunningBundles(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedRunningBundles(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedRunningBundles(napi_env env, napi_callback_info info);
    static napi_value AddAutoStartApps(napi_env env, napi_callback_info info);
    static napi_value RemoveAutoStartApps(napi_env env, napi_callback_info info);
    static napi_value GetAutoStartApps(napi_env env, napi_callback_info info);
    static napi_value AddDisallowedRunningBundlesSync(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedRunningBundlesSync(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedRunningBundlesSync(napi_env env, napi_callback_info info);
    static napi_value AddAllowedRunningBundles(napi_env env, napi_callback_info info);
    static napi_value RemoveAllowedRunningBundles(napi_env env, napi_callback_info info);
    static napi_value GetAllowedRunningBundles(napi_env env, napi_callback_info info);
    static napi_value AddKeepAliveApps(napi_env env, napi_callback_info info);
    static napi_value RemoveKeepAliveApps(napi_env env, napi_callback_info info);
    static napi_value GetKeepAliveApps(napi_env env, napi_callback_info info);
    static napi_value SetKioskFeatures(napi_env env, napi_callback_info info);
    static napi_value SetAllowedKioskApps(napi_env env, napi_callback_info info);
    static napi_value GetAllowedKioskApps(napi_env env, napi_callback_info info);
    static napi_value IsAppKioskAllowed(napi_env env, napi_callback_info info);
    static napi_value ClearUpApplicationData(napi_env env, napi_callback_info info);
    static napi_value IsModifyKeepAliveAppsDisallowed(napi_env env, napi_callback_info info);
    static napi_value IsModifyAutoStartAppsDisallowed(napi_env env, napi_callback_info info);
    static napi_value AddFreezeExemptedApps(napi_env env, napi_callback_info info);
    static napi_value RemoveFreezeExemptedApps(napi_env env, napi_callback_info info);
    static napi_value GetFreezeExemptedApps(napi_env env, napi_callback_info info);

private:
    static napi_value AddOrRemoveDisallowedRunningBundles(napi_env env, napi_callback_info info,
        const std::string &workName, napi_async_execute_callback execute);
    static napi_value AddOrRemoveAutoStartApps(napi_env env, napi_callback_info info, std::string function);
    static napi_value AddOrRemoveDisallowedRunningBundlesSync(napi_env env, napi_callback_info info, bool isAdd);
    static napi_value AddOrRemoveAllowedRunningBundles(napi_env env, napi_callback_info info, bool isAdd);
    static napi_value AddOrRemoveKeepAliveApps(napi_env env, napi_callback_info info, std::string function);
    static napi_value AddOrRemoveFreezeExemptedApps(napi_env env, napi_callback_info info, std::string function);

    static void CreateKioskFeatureObject(napi_env env, napi_value value);
    static void NativeAddDisallowedRunningBundles(napi_env env, void *data);
    static void NativeRemoveDisallowedRunningBundles(napi_env env, void *data);
    static void NativeGetDisallowedRunningBundles(napi_env env, void *data);
    static bool CheckAddDisallowedRunningBundlesParamType(napi_env env, size_t argc,
        napi_value* argv, bool &hasCallback, bool &hasUserId);
    static std::shared_ptr<ApplicationManagerProxy> applicationManagerProxy_;
    static void SetBaseDataForGetPolicy(int32_t userId, MessageParcel &data);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_APPLICATION_MANAGER_INCLUDE_APPLICATION__MANAGER_ADDON_H
