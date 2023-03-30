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

#ifndef INTERFACES_KITS_BUNDLE_MANAGER_INCLUDE_BUNDLE_MANAGER_ADDON_H
#define INTERFACES_KITS_BUNDLE_MANAGER_INCLUDE_BUNDLE_MANAGER_ADDON_H

#include "bundle_manager_proxy.h"
#include "edm_errors.h"
#include "napi_edm_error.h"
#include "napi_edm_common.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi/native_api.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncAllowedInstallBundlesCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::vector<std::string> bundles;
    int32_t userId = 0;
};

class BundleManagerAddon {
public:
    BundleManagerAddon();
    ~BundleManagerAddon() = default;

    static napi_value Init(napi_env env, napi_value exports);

    static napi_value AddAllowedInstallBundles(napi_env env, napi_callback_info info);
    static napi_value RemoveAllowedInstallBundles(napi_env env, napi_callback_info info);
    static napi_value GetAllowedInstallBundles(napi_env env, napi_callback_info info);

private:
    static napi_value AddOrRemovellowedInstallBundles(napi_env env, napi_callback_info info,
        const std::string &workName, napi_async_execute_callback execute);

    static void NativeAddAllowedInstallBundles(napi_env env, void *data);
    static void NativeRemoveAllowedInstallBundles(napi_env env, void *data);
    static void NativeGetAllowedInstallBundles(napi_env env, void *data);

    static bool CheckAddAllowedInstallBundlesParamType(napi_env env, size_t argc,
        napi_value* argv, bool &hasCallback, bool &hasUserId);
    static std::shared_ptr<BundleManagerProxy> bundleManagerProxy_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_BUNDLE_MANAGER_INCLUDE_BUNDLE_MANAGER_ADDON_H
