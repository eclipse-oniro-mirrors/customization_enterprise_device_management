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

#ifndef INTERFACES_KITS_BUNDLE_MANAGER_INCLUDE_BUNDLE_MANAGER_ADDON_H
#define INTERFACES_KITS_BUNDLE_MANAGER_INCLUDE_BUNDLE_MANAGER_ADDON_H

#include "bundle_manager_proxy.h"
#include "edm_errors.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "want.h"
#include "edm_bundle_info.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
struct AsyncBundlesCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::vector<std::string> bundles;
    int32_t userId = 0;
    int32_t policyType = 0;
};

struct AsyncUninstallCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::string bundleName;
    int32_t userId = 0;
    bool isKeepData = false;
};

struct AsyncBundleInfoCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    int32_t userId = 0;
    std::vector<EdmBundleInfo> bundleInfos;
};

#ifdef BUNDLE_FRAMEWORK_EDM_ENABLE
struct AsyncInstallCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::vector<std::string> hapFilePaths;
    OHOS::AppExecFwk::InstallParam installParam;
};
#endif

class BundleManagerAddon {
public:
    BundleManagerAddon();
    ~BundleManagerAddon() = default;

    static napi_value Init(napi_env env, napi_value exports);

    static napi_value AddAllowedInstallBundles(napi_env env, napi_callback_info info);
    static napi_value RemoveAllowedInstallBundles(napi_env env, napi_callback_info info);
    static napi_value GetAllowedInstallBundles(napi_env env, napi_callback_info info);
    static napi_value AddDisallowedInstallBundles(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedInstallBundles(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedInstallBundles(napi_env env, napi_callback_info info);
    static napi_value AddDisallowedUninstallBundles(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedUninstallBundles(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedUninstallBundles(napi_env env, napi_callback_info info);
    static napi_value Uninstall(napi_env env, napi_callback_info info);
    static napi_value Install(napi_env env, napi_callback_info info);
    static napi_value AddAllowedInstallBundlesSync(napi_env env, napi_callback_info info);
    static napi_value RemoveAllowedInstallBundlesSync(napi_env env, napi_callback_info info);
    static napi_value GetAllowedInstallBundlesSync(napi_env env, napi_callback_info info);
    static napi_value AddDisallowedInstallBundlesSync(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedInstallBundlesSync(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedInstallBundlesSync(napi_env env, napi_callback_info info);
    static napi_value AddDisallowedUninstallBundlesSync(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedUninstallBundlesSync(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedUninstallBundlesSync(napi_env env, napi_callback_info info);
    static napi_value GetInstalledBundleList(napi_env env, napi_callback_info info);
    static napi_value AddInstallationAllowedAppDistributionTypes(napi_env env, napi_callback_info info);
    static napi_value removeInstallationAllowedAppDistributionTypes(napi_env env, napi_callback_info info);
    static napi_value AddOrRemoveInstallationAllowedAppDistributionTypes(napi_env env, napi_callback_info info,
        FuncOperateType operateType);
    static napi_value GetInstallationAllowedAppDistributionTypes(napi_env env, napi_callback_info info);

private:
    static napi_value AddOrRemoveInstallBundles(napi_env env, napi_callback_info info, const std::string &workName,
        napi_async_execute_callback execute);
    static napi_value GetAllowedOrDisallowedInstallBundles(napi_env env, napi_callback_info info,
        const std::string &workName, napi_async_execute_callback execute);

    static void NativeAddBundlesByPolicyType(napi_env env, void *data);
    static void NativeRemoveBundlesByPolicyType(napi_env env, void *data);
    static void NativeGetBundlesByPolicyType(napi_env env, void *data);
    static void InitCallbackInfoPolicyType(const std::string &workName, AsyncBundlesCallbackInfo *callback);
    static void NativeUninstall(napi_env env, void *data);
    static void NativeUninstallCallbackComplete(napi_env env, napi_status status, void *data);
    static void NativeInstall(napi_env env, void *data);
    static void NativeGetInstalledBundleList(napi_env env, void *data);
    static void NativeGetInstalledBundleListComplete(napi_env env, napi_status status, void *data);
    static bool CheckAddInstallBundlesParamType(napi_env env, size_t argc, napi_value *argv, bool &hasCallback,
        bool &hasUserId);
    static bool CheckAndParseUninstallParamType(napi_env env, size_t argc, napi_value *argv,
        AsyncUninstallCallbackInfo *asyncCallbackInfo);
    static void CreateAppDistributionTypeObject(napi_env env, napi_value value);
#ifdef BUNDLE_FRAMEWORK_EDM_ENABLE
    static bool CheckAndParseInstallParamType(napi_env env, size_t argc, napi_value *argv,
        AsyncInstallCallbackInfo *asyncCallbackInfo);
    static bool jsObjectToInstallParam(napi_env env, napi_value object, OHOS::AppExecFwk::InstallParam &installParam);
    static bool ParseParameters(napi_env env, napi_value object, std::map<std::string, std::string> &parameters);
    static void ConvertVectorBundleToJs(napi_env env, const std::vector<EdmBundleInfo> &bundleVector,
        napi_value &result);
    static void ConvertResource(napi_env env, const EdmResource &resource, napi_value objResource);
    static void ConvertApplicationInfo(napi_env env, napi_value objAppInfo, const EdmApplicationInfo &appInfo);
    static void ConvertSignatureInfo(napi_env env, const EdmSignatureInfo &signatureInfo, napi_value value);
    static void ConvertBundleInfo(napi_env env, const EdmBundleInfo &bundleInfo, napi_value objBundleInfo);
#endif
    static napi_value AddOrRemoveInstallBundlesSync(napi_env env, napi_callback_info info, const std::string &workName,
        bool isAdd);
    static void InitPolicyType(const std::string &workName, int32_t &policyType);
    static napi_value GetAllowedOrDisallowedInstallBundlesSync(napi_env env, napi_callback_info info,
        const std::string &workName);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_BUNDLE_MANAGER_INCLUDE_BUNDLE_MANAGER_ADDON_H
