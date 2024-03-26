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

#ifndef INTERFACES_KITS_BROWSER_BROWSER_ADDON_H
#define INTERFACES_KITS_BROWSER_BROWSER_ADDON_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncBrowserCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::string appId;
    std::string policies;
    napi_value value;
};

class BrowserAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);

    static napi_value SetPolicies(napi_env env, napi_callback_info info);
    static napi_value GetPolicies(napi_env env, napi_callback_info info);
    static napi_value SetPolicy(napi_env env, napi_callback_info info);
    static napi_value GetPoliciesSync(napi_env env, napi_callback_info info);

private:
    static void NativeSetPolicies(napi_env env, void *data);
    static void NativeGetPolicies(napi_env env, void *data);
    static napi_value SetPolicyCommon(napi_env env, napi_callback_info info, AsyncBrowserCallbackInfo* callbackInfo);
    static napi_value GetPoliciesCommon(napi_env env, napi_callback_info info, AsyncBrowserCallbackInfo* callbackInfo);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_BROWSER_BROWSER_ADDON_H
