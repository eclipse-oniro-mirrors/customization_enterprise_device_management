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
#include "napi_edm_element_name.h"
#include "net_stats_utils.h"

namespace OHOS {
namespace EDM {
struct AsyncDisallowedRunningBundlesCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::vector<std::string> appIds;
    int32_t userId = 0;
};

struct AsyncQueryTrafficStatsCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    NetStatsNetwork networkInfo;
    NetStatsInfo netStatsInfo;
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
    static napi_value AddUserNonStopApps(napi_env env, napi_callback_info info);
    static napi_value RemoveUserNonStopApps(napi_env env, napi_callback_info info);
    static napi_value GetUserNonStopApps(napi_env env, napi_callback_info info);
    static napi_value SetAbilityDisabled(napi_env env, napi_callback_info info);
    static napi_value IsAbilityDisabled(napi_env env, napi_callback_info info);
    static napi_value AddDockApp(napi_env env, napi_callback_info info);
    static napi_value RemoveDockApp(napi_env env, napi_callback_info info);
    static napi_value GetDockApps(napi_env env, napi_callback_info info);
    static napi_value AddAllowedNotificationBundles(napi_env env, napi_callback_info info);
    static napi_value RemoveAllowedNotificationBundles(napi_env env, napi_callback_info info);
    static napi_value GetAllowedNotificationBundles(napi_env env, napi_callback_info info);
    static napi_value QueryTrafficStats(napi_env env, napi_callback_info info);
    static napi_value QueryBundleStatsInfos(napi_env env, napi_callback_info info);

private:
    static napi_value AddOrRemoveDisallowedRunningBundles(napi_env env, napi_callback_info info,
        const std::string &workName, napi_async_execute_callback execute);
    static napi_value AddOrRemoveAutoStartApps(napi_env env, napi_callback_info info, std::string function);
    static napi_value AddOrRemoveDisallowedRunningBundlesSync(napi_env env, napi_callback_info info, bool isAdd);
    static napi_value AddOrRemoveAllowedRunningBundles(napi_env env, napi_callback_info info, bool isAdd);
    static napi_value AddOrRemoveKeepAliveApps(napi_env env, napi_callback_info info, std::string function);
    static napi_value AddOrRemoveFreezeExemptedApps(napi_env env, napi_callback_info info, std::string function);
    static napi_value AddOrRemoveUserNonStopApps(napi_env env, napi_callback_info info, std::string function);
    static napi_value AddOrRemoveDockApp(napi_env env, napi_callback_info info, std::string function);
    static bool EdmParseElementName(napi_env env, OHOS::EDM::EdmElementName &elementName, napi_value args);
    static napi_value EdmParseElementArray(napi_env env, std::vector<OHOS::EDM::EdmElementName> &elementArray,
        napi_value args);
    static napi_value ParseAutoStartAppsInfo(napi_env env, napi_value &napiAutoStartApps,
        std::vector<EdmElementName> autoStartApps);

    static void CreateKioskFeatureObject(napi_env env, napi_value value);
    static void NativeAddDisallowedRunningBundles(napi_env env, void *data);
    static void NativeRemoveDisallowedRunningBundles(napi_env env, void *data);
    static void NativeGetDisallowedRunningBundles(napi_env env, void *data);
    static bool CheckAddDisallowedRunningBundlesParamType(napi_env env, size_t argc,
        napi_value* argv, bool &hasCallback, bool &hasUserId);
    static std::shared_ptr<ApplicationManagerProxy> applicationManagerProxy_;
    static void SetBaseDataForGetPolicy(int32_t userId, MessageParcel &data);
    static void JoinParcelData(MessageParcel &parcelData, int32_t userId,
        OHOS::AppExecFwk::ElementName &elementName, std::vector<OHOS::EDM::EdmElementName> autoStartApps);
    static bool ParseNetworkInfo(napi_env env, NetStatsNetwork &networkInfo, napi_value args);
    static void NativeQueryTrafficStats(napi_env env, void *data);
    static void NativeQueryTrafficStatsComplete(napi_env env, napi_status status, void *data);
#ifdef FEATURE_PC_ONLY
    static void ConvertDockInfoVectorToJs(napi_env env, const std::vector<DockInfo> &dockInfos, napi_value &nDockInfos);
#endif
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_APPLICATION_MANAGER_INCLUDE_APPLICATION__MANAGER_ADDON_H
