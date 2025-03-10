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

#ifndef INTERFACES_KITS_ACCOUNT_MANAGER_INCLUDE_ACCOUNT_MANAGER_ADDON_H
#define INTERFACES_KITS_ACCOUNT_MANAGER_INCLUDE_ACCOUNT_MANAGER_ADDON_H

#ifdef OS_ACCOUNT_EDM_ENABLE
#include "account_info.h"
#include "os_account_info.h"
#endif
#include "account_manager_proxy.h"
#include "domain_account_policy.h"
#include "edm_errors.h"
#include "napi_edm_error.h"
#include "napi_edm_common.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi/native_api.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncDisallowAddLocalAccountCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    bool isDisallow;
};
#ifdef OS_ACCOUNT_EDM_ENABLE
struct AsyncAddOsAccountCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::string name;
    int32_t type;
    OHOS::AccountSA::OsAccountInfo accountInfo;
};
#endif
class AccountManagerAddon {
public:
    AccountManagerAddon();
    ~AccountManagerAddon() = default;

    static napi_value Init(napi_env env, napi_value exports);
private:
    static napi_value DisallowAddLocalAccount(napi_env env, napi_callback_info info);
    static void NativeDisallowAddLocalAccount(napi_env env, void *data);
    static napi_value DisallowAddOsAccountByUser(napi_env env, napi_callback_info info);
    static napi_value IsAddOsAccountByUserDisallowed(napi_env env, napi_callback_info info);
    static napi_value AddOsAccount(napi_env env, napi_callback_info info);
    static bool CheckOsAccountType(int32_t type);
    static napi_value MakeArrayToJs(napi_env env, const std::vector<std::string> &constraints, napi_value jsArray);
#ifdef OS_ACCOUNT_EDM_ENABLE
    static napi_value CreateJsDomainInfo(napi_env env, const OHOS::AccountSA::DomainAccountInfo &info,
        napi_value &result);
    static napi_value ConvertOsAccountInfoToJs(napi_env env, OHOS::AccountSA::OsAccountInfo &info);
    static napi_value AddOsAccountCommon(napi_env env, napi_callback_info info,
        AsyncAddOsAccountCallbackInfo* callbackInfo);
    static void NativeAddOsAccount(napi_env env, void *data);
    static void NativeAddOsAccountCallbackComplete(napi_env env, napi_status status, void *data);
#endif
    static napi_value DisallowAddOsAccount(napi_env env, napi_callback_info info);
    static napi_value IsAddOsAccountDisallowed(napi_env env, napi_callback_info info);
    static napi_value AddOsAccountAsync(napi_env env, napi_callback_info info);
    static napi_value SetDomainAccountPolicy(napi_env env, napi_callback_info info);
    static napi_value GetDomainAccountPolicy(napi_env env, napi_callback_info info);
    static napi_value ConvertDomainAccountPolicyToJs(napi_env env, DomainAccountPolicy &domainAccountPolicy);
    static bool ParseDomainAccountPolicy(napi_env env, DomainAccountPolicy &domainAccountPolicy, napi_value args);
#if defined(FEATURE_PC_ONLY) && defined(OS_ACCOUNT_EDM_ENABLE)
    static bool ParseDomainAccountInfo(napi_env env, OHOS::AccountSA::DomainAccountInfo &domainAccountInfo,
        napi_value args);
#endif
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_ACCOUNT_MANAGER_INCLUDE_ACCOUNT_MANAGER_ADDON_H
