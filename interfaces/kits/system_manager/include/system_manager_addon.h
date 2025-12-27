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

#ifndef INTERFACES_KITS_SYSTEM_MANAGER_INCLUDE_SYSTEM_MANAGER_ADDON_H
#define INTERFACES_KITS_SYSTEM_MANAGER_INCLUDE_SYSTEM_MANAGER_ADDON_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "want.h"

#include "edm_errors.h"
#include "func_code.h"
#include "system_manager_proxy.h"
#include "update_policy_utils.h"

namespace OHOS {
namespace EDM {
struct AsyncGetUpgradeResultCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::string version;
    UpgradeResult upgradeResult;
};

struct AsyncNotifyUpdatePackagesCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    UpgradePackageInfo packageInfo;
};

struct AsyncStartCollectLogCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
};

enum class NearlinkProtocol : uint32_t { SSAP = 0, DATA_TRANSFER = 1 };

class SystemManagerAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static void AddFunctionsToExports(napi_env env, napi_value exports);
    static void AddEnumsToExports(napi_env env, napi_value exports);

private:
    static napi_value SetNTPServer(napi_env env, napi_callback_info info);
    static napi_value GetNTPServer(napi_env env, napi_callback_info info);
    static napi_value SetOTAUpdatePolicy(napi_env env, napi_callback_info info);
    static napi_value GetOTAUpdatePolicy(napi_env env, napi_callback_info info);
    static napi_value NotifyUpdatePackages(napi_env env, napi_callback_info info);
    static napi_value GetUpgradeResult(napi_env env, napi_callback_info info);
    static napi_value GetUpdateAuthData(napi_env env, napi_callback_info info);
    static napi_value SetAutoUnlockAfterReboot(napi_env env, napi_callback_info info);
    static napi_value GetAutoUnlockAfterReboot(napi_env env, napi_callback_info info);
    static void CreatePolicyTypeObject(napi_env env, napi_value value);
    static void CreatePackageTypeObject(napi_env env, napi_value value);
    static void CreateUpgradeStatusObject(napi_env env, napi_value value);
    static bool JsObjToUpdatePolicy(napi_env env, napi_value object, UpdatePolicy &updatePolicy, std::string &errorMsg);
    static napi_value ConvertUpdatePolicyToJs(napi_env env, const UpdatePolicy &updatePolicy);
    static napi_value ConvertUpdateResultToJs(napi_env env, const UpgradeResult &updateResult);
    static bool JsObjToUpgradePackageInfo(napi_env env, napi_value object, UpgradePackageInfo &packageInfo);
    static bool ParsePackages(napi_env env, napi_value object, std::vector<Package> &packages);
    static bool ParsePackage(napi_env env, napi_value object, Package &package);
    static bool ParseDescription(napi_env env, napi_value object, PackageDescription &description);
    static void NativeNotifyUpdatePackages(napi_env env, void *data);
    static void NativeGetUpgradeResult(napi_env env, void *data);
    static void NativeGetUpdateAuthData(napi_env env, void *data);
    static void NativeUpgradeResultComplete(napi_env env, napi_status status, void *data);
    static bool JsDisableSystemOtaUpdateToUpdatePolicy(napi_env env, napi_value object, const char *filedStr,
        OtaPolicyType &otaPolicyType);
    static napi_value SetInstallLocalEnterpriseAppEnabled(napi_env env, napi_callback_info info);
    static napi_value GetInstallLocalEnterpriseAppEnabled(napi_env env, napi_callback_info info);
    static napi_value AddDisallowedNearlinkProtocols(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedNearlinkProtocols(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedNearlinkProtocols(napi_env env, napi_callback_info info);
    static napi_value AddOrRemoveDisallowedNearlinkProtocols(napi_env env, napi_callback_info info,
        FuncOperateType operateType);
    static void CreateProtocolObject(napi_env env, napi_value value);
    static napi_value StartCollectLog(napi_env env, napi_callback_info info);
    static napi_value AddKeyEventPolicies(napi_env env, napi_callback_info info);
    static napi_value RemoveKeyEventPolicies(napi_env env, napi_callback_info info);
    static napi_value GetKeyEventPolicies(napi_env env, napi_callback_info info);
    static void CreateKeyCodeObject(napi_env env, napi_value value);
    static void CreateKeyActionObject(napi_env env, napi_value value);
    static void CreateKeyPolicyObject(napi_env env, napi_value value);
#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
    static void NativeStartCollectLog(napi_env env, void *data);
#endif
    static napi_value FinishLogCollected(napi_env env, napi_callback_info info);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_SYSTEM_MANAGER_INCLUDE_SYSTEM_MANAGER_ADDON_H
