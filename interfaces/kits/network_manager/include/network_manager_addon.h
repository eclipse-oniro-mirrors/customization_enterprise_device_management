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

#ifndef INTERFACES_KITS_NETWORK_MANAGER_INCLUDE_NETWORK_MANAGER_ADDON_H
#define INTERFACES_KITS_NETWORK_MANAGER_INCLUDE_NETWORK_MANAGER_ADDON_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "network_manager_proxy.h"
#include "want.h"

#include "domain_filter_rule.h"
#include "firewall_rule.h"
#include "iptables_utils.h"

namespace OHOS {
namespace EDM {
struct AsyncNetworkInfoCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::string networkInterface;
    int policyCode = 0;
};

struct AsyncNetworkInterfacesCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
};

struct AsyncSetNetworkInterfaceCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    std::string networkInterface;
    bool isDisabled = false;
};

struct AsyncIptablesCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    IPTABLES::AddFilter addFilter;
    IPTABLES::RemoveFilter removeFilter;
};

#ifdef NETMANAGER_BASE_EDM_ENABLE
struct AsyncHttpProxyCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    OHOS::NetManagerStandard::HttpProxy httpProxy;
    bool hasAdmin = false;
};
#endif

class NetworkManagerAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value GetAllNetworkInterfaces(napi_env env, napi_callback_info info);
    static napi_value GetIpAddress(napi_env env, napi_callback_info info);
    static napi_value GetMac(napi_env env, napi_callback_info info);
    static napi_value GetIpOrMacAddress(napi_env env, napi_callback_info info, int policyCode);
    static napi_value SetNetworkInterfaceDisabled(napi_env env, napi_callback_info info);
    static napi_value IsNetworkInterfaceDisabled(napi_env env, napi_callback_info info);
    static napi_value AddIptablesFilterRule(napi_env env, napi_callback_info info);
    static napi_value RemoveIptablesFilterRule(napi_env env, napi_callback_info info);
    static napi_value ListIptablesFilterRules(napi_env env, napi_callback_info info);
    static napi_value AddFirewallRule(napi_env env, napi_callback_info info);
    static napi_value RemoveFirewallRule(napi_env env, napi_callback_info info);
    static napi_value GetFirewallRules(napi_env env, napi_callback_info info);
    static napi_value AddDomainFilterRule(napi_env env, napi_callback_info info);
    static napi_value RemoveDomainFilterRule(napi_env env, napi_callback_info info);
    static napi_value GetDomainFilterRules(napi_env env, napi_callback_info info);
    static void NativeGetAllNetworkInterfaces(napi_env env, void *data);
    static void NativeGetIpOrMacAddress(napi_env env, void *data);
    static void NativeSetNetworkInterfaceDisabled(napi_env env, void *data);
    static void NativeIsNetworkInterfaceDisabled(napi_env env, void *data);
    static void NativeAddIptalbsFilterRule(napi_env env, void *data);
    static void NativeRemoveIptalbsFilterRule(napi_env env, void *data);
    static void NativeListIptablesFilterRules(napi_env env, void *data);
    static void CreateFirewallActionObject(napi_env env, napi_value value);
    static void CreateFirewallProtocolObject(napi_env env, napi_value value);
    static void CreateFirewallDirectionObject(napi_env env, napi_value value);
    static void CreateFirewallAddMethodObject(napi_env env, napi_value value);
    static bool JsObjToAddFirewallObject(napi_env env, napi_value object, IPTABLES::AddFilter &addFilter);
    static bool JsObjToRemoveFirewallObject(napi_env env, napi_value object, IPTABLES::RemoveFilter &removeFilter);
    static bool JsObjToFirewallRule(napi_env env, napi_value object, IPTABLES::FirewallRule &rule);
    static napi_value FirewallRuleToJsObj(napi_env env, const IPTABLES::FirewallRule &rule);
    static bool JsObjToDomainFilterRule(napi_env env, napi_value object, IPTABLES::DomainFilterRule &rule);
    static napi_value DomainFilterRuleToJsObj(napi_env env, const IPTABLES::DomainFilterRule &rule);

    static napi_value SetGlobalHttpProxy(napi_env env, napi_callback_info info);
    static napi_value GetGlobalHttpProxy(napi_env env, napi_callback_info info);
#ifdef NETMANAGER_BASE_EDM_ENABLE
    static bool ParseHttpProxyParam(napi_env env, napi_value argv, NetManagerStandard::HttpProxy &httpProxy);
    static napi_value ConvertHttpProxyToJS(napi_env env, const OHOS::NetManagerStandard::HttpProxy &httpProxy);
    static void NativeSetGlobalHttpProxy(napi_env env, void *data);
    static void NativeGetGlobalHttpProxy(napi_env env, void *data);
    static void NativeHttpProxyCallbackComplete(napi_env env, napi_status status, void *data);
    static bool JsObjectToSecureData(napi_env env, napi_value object, const char *paramStr,
        OHOS::NetManagerStandard::SecureData &secureData);
    static bool ParseSecureData(napi_env env, OHOS::NetManagerStandard::SecureData &secureData, napi_value object);
    static bool GetSecureDataFromNAPI(napi_env env, napi_value object,
        OHOS::NetManagerStandard::SecureData &secureData);
#endif
    static napi_value GetAllNetworkInterfacesSync(napi_env env, napi_callback_info info);
    static napi_value GetIpAddressSync(napi_env env, napi_callback_info info);
    static napi_value GetMacSync(napi_env env, napi_callback_info info);
    static napi_value GetIpOrMacAddressSync(napi_env env, napi_callback_info info, int policyCode);
    static napi_value SetNetworkInterfaceDisabledSync(napi_env env, napi_callback_info info);
    static napi_value IsNetworkInterfaceDisabledSync(napi_env env, napi_callback_info info);
    static napi_value SetGlobalHttpProxySync(napi_env env, napi_callback_info info);
    static napi_value GetGlobalHttpProxySync(napi_env env, napi_callback_info info);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_NETWORK_MANAGER_INCLUDE_NETWORK_MANAGER_ADDON_H
