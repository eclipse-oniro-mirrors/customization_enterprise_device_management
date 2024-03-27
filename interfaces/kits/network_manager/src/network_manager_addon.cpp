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
#include "network_manager_addon.h"

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iptables_utils.h"
#include "napi_edm_common.h"

using namespace OHOS::EDM;
using namespace OHOS::EDM::IPTABLES;

#ifdef NETMANAGER_BASE_EDM_ENABLE
const char *const HOST_PROP_NAME = "host";
const char *const PORT_PROP_NAME = "port";
const char *const PROXY_USER_NAME = "username";
const char *const PROXY_PASSWORD = "password";
const char *const EXCLUSION_LIST_PROP_NAME = "exclusionList";
#endif

void NetworkManagerAddon::CreateFirewallActionObject(napi_env env, napi_value value)
{
    napi_value nAllow;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::Action::ALLOW), &nAllow));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ALLOW", nAllow));
    napi_value nDeny;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::Action::DENY), &nDeny));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DENY", nDeny));
}

void NetworkManagerAddon::CreateFirewallProtocolObject(napi_env env, napi_value value)
{
    napi_value nAll;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::Protocol::ALL), &nAll));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ALL", nAll));
    napi_value nTCP;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::Protocol::TCP), &nTCP));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "TCP", nTCP));
    napi_value nUDP;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::Protocol::UDP), &nUDP));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UDP", nUDP));
    napi_value nICMP;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::Protocol::ICMP), &nICMP));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ICMP", nICMP));
}

void NetworkManagerAddon::CreateFirewallDirectionObject(napi_env env, napi_value value)
{
    napi_value nInput;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::Direction::INPUT), &nInput));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "INPUT", nInput));
    napi_value nOutput;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::Direction::OUTPUT), &nOutput));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "OUTPUT", nOutput));
}

void NetworkManagerAddon::CreateFirewallAddMethodObject(napi_env env, napi_value value)
{
    napi_value nAppend;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::AddMethod::APPEND), &nAppend));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "APPEND", nAppend));
    napi_value nInsert;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IPTABLES::AddMethod::INSERT), &nInsert));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "INSERT", nInsert));
}

napi_value NetworkManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value nFirewallAction = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nFirewallAction));
    CreateFirewallActionObject(env, nFirewallAction);

    napi_value nFirewallProtocol = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nFirewallProtocol));
    CreateFirewallProtocolObject(env, nFirewallProtocol);

    napi_value nFirewallDirection = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nFirewallDirection));
    CreateFirewallDirectionObject(env, nFirewallDirection);

    napi_value nFirewallAddMethod = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nFirewallAddMethod));
    CreateFirewallAddMethodObject(env, nFirewallAddMethod);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("getAllNetworkInterfaces", GetAllNetworkInterfaces),
        DECLARE_NAPI_FUNCTION("getIpAddress", GetIpAddress),
        DECLARE_NAPI_FUNCTION("getMac", GetMac),
        DECLARE_NAPI_FUNCTION("setNetworkInterfaceDisabled", SetNetworkInterfaceDisabled),
        DECLARE_NAPI_FUNCTION("isNetworkInterfaceDisabled", IsNetworkInterfaceDisabled),

        DECLARE_NAPI_PROPERTY("Action", nFirewallAction),
        DECLARE_NAPI_PROPERTY("Protocol", nFirewallProtocol),
        DECLARE_NAPI_PROPERTY("Direction", nFirewallDirection),
        DECLARE_NAPI_PROPERTY("AddMethod", nFirewallAddMethod),
        DECLARE_NAPI_FUNCTION("addIptablesFilterRule", AddIptablesFilterRule),
        DECLARE_NAPI_FUNCTION("removeIptablesFilterRule", RemoveIptablesFilterRule),
        DECLARE_NAPI_FUNCTION("listIptablesFilterRules", ListIptablesFilterRules),

        DECLARE_NAPI_FUNCTION("addFirewallRule", AddFirewallRule),
        DECLARE_NAPI_FUNCTION("removeFirewallRule", RemoveFirewallRule),
        DECLARE_NAPI_FUNCTION("getFirewallRules", GetFirewallRules),

        DECLARE_NAPI_FUNCTION("addDomainFilterRule", AddDomainFilterRule),
        DECLARE_NAPI_FUNCTION("removeDomainFilterRule", RemoveDomainFilterRule),
        DECLARE_NAPI_FUNCTION("getDomainFilterRules", GetDomainFilterRules),

        DECLARE_NAPI_FUNCTION("setGlobalProxy", SetGlobalHttpProxy),
        DECLARE_NAPI_FUNCTION("getGlobalProxy", GetGlobalHttpProxy),

        DECLARE_NAPI_FUNCTION("getAllNetworkInterfacesSync", GetAllNetworkInterfacesSync),
        DECLARE_NAPI_FUNCTION("getIpAddressSync", GetIpAddressSync),
        DECLARE_NAPI_FUNCTION("getMacSync", GetMacSync),
        DECLARE_NAPI_FUNCTION("setNetworkInterfaceDisabledSync", SetNetworkInterfaceDisabledSync),
        DECLARE_NAPI_FUNCTION("isNetworkInterfaceDisabledSync", IsNetworkInterfaceDisabledSync),
        DECLARE_NAPI_FUNCTION("setGlobalProxySync", SetGlobalHttpProxySync),
        DECLARE_NAPI_FUNCTION("getGlobalProxySync", GetGlobalHttpProxySync),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value NetworkManagerAddon::GetAllNetworkInterfaces(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    if (argc > ARGS_SIZE_ONE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARGS_SIZE_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncNetworkInterfacesCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncNetworkInterfacesCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "GetAllNetworkInterfaces: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("NAPI_GetAllNetworkInterfaces argc == ARGS_SIZE_TWO");
        napi_create_reference(env, argv[ARGS_SIZE_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "GetAllNetworkInterface",
        NativeGetAllNetworkInterfaces, NativeArrayStringCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void NetworkManagerAddon::NativeGetAllNetworkInterfaces(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetAllNetworkInterfaces called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncNetworkInterfacesCallbackInfo *asyncCallbackInfo = static_cast<AsyncNetworkInterfacesCallbackInfo *>(data);
    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = networkManagerProxy->GetAllNetworkInterfaces(asyncCallbackInfo->elementName,
        asyncCallbackInfo->arrayStringRet);
}

napi_value NetworkManagerAddon::GetIpAddress(napi_env env, napi_callback_info info)
{
    EDMLOGI("NetworkManagerAddon::GetIpAddress called");
    return GetIpOrMacAddress(env, info, EdmInterfaceCode::GET_IP_ADDRESS);
}

napi_value NetworkManagerAddon::GetMac(napi_env env, napi_callback_info info)
{
    EDMLOGI("NetworkManagerAddon::GetMac called");
    return GetIpOrMacAddress(env, info, EdmInterfaceCode::GET_MAC);
}

napi_value NetworkManagerAddon::GetIpOrMacAddress(napi_env env, napi_callback_info info, int policyCode)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag =
        MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) && MatchValueType(env, argv[ARR_INDEX_ONE], napi_string);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARGS_SIZE_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncNetworkInfoCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncNetworkInfoCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->networkInterface, argv[ARR_INDEX_ONE]),
        "parameter networkInterface error");
    EDMLOGD(
        "GetIpOrMacAddress: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_GetIpOrMacAddress argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    asyncCallbackInfo->policyCode = policyCode;
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "GetIpAddress", NativeGetIpOrMacAddress, NativeStringCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void NetworkManagerAddon::NativeGetIpOrMacAddress(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetIpOrMacAddress called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncNetworkInfoCallbackInfo *asyncCallbackInfo = static_cast<AsyncNetworkInfoCallbackInfo *>(data);
    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = networkManagerProxy->GetIpOrMacAddress(asyncCallbackInfo->elementName,
        asyncCallbackInfo->networkInterface, asyncCallbackInfo->policyCode, asyncCallbackInfo->stringRet);
}

napi_value NetworkManagerAddon::SetNetworkInterfaceDisabled(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_string) && MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean);
    if (argc > ARGS_SIZE_THREE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARGS_SIZE_THREE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncSetNetworkInterfaceCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSetNetworkInterfaceCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "parameter element name error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->networkInterface, argv[ARR_INDEX_ONE]),
        "parameter networkInterface error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, asyncCallbackInfo->isDisabled, argv[ARR_INDEX_TWO]),
        "parameter isDisabled error");
    EDMLOGD(
        "SetNetworkInterfaceDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_THREE) {
        EDMLOGD("NAPI_SetNetworkInterfaceDisabled argc == ARGS_SIZE_FOUR");
        napi_create_reference(env, argv[ARGS_SIZE_THREE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "SetNetworkInterfaceDisabled",
        NativeSetNetworkInterfaceDisabled, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void NetworkManagerAddon::NativeSetNetworkInterfaceDisabled(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetNetworkInterfaceDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncSetNetworkInterfaceCallbackInfo *asyncCallbackInfo = static_cast<AsyncSetNetworkInterfaceCallbackInfo *>(data);
    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = networkManagerProxy->SetNetworkInterfaceDisabled(asyncCallbackInfo->elementName,
        asyncCallbackInfo->networkInterface, asyncCallbackInfo->isDisabled);
}

napi_value NetworkManagerAddon::IsNetworkInterfaceDisabled(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag =
        MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) && MatchValueType(env, argv[ARR_INDEX_ONE], napi_string);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARGS_SIZE_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncNetworkInfoCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncNetworkInfoCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "parameter element name error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->networkInterface, argv[ARR_INDEX_ONE]),
        "parameter networkInterface error");
    EDMLOGD(
        "IsNetworkInterfaceDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_IsNetworkInterfaceDisabled argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "IsNetworkInterfaceDisabled",
        NativeIsNetworkInterfaceDisabled, NativeBoolCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void NetworkManagerAddon::NativeIsNetworkInterfaceDisabled(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeIsNetworkInterfaceDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncNetworkInfoCallbackInfo *asyncCallbackInfo = static_cast<AsyncNetworkInfoCallbackInfo *>(data);
    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = networkManagerProxy->IsNetworkInterfaceDisabled(asyncCallbackInfo->elementName,
        asyncCallbackInfo->networkInterface, asyncCallbackInfo->boolRet);
}

napi_value NetworkManagerAddon::AddIptablesFilterRule(napi_env env, napi_callback_info info)
{
    EDMLOGI("NetworkManagerAddon::AddIptablesFilterRule called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncIptablesCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncIptablesCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "AddIptalbsFilterRule: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToAddFirewallObject(env, argv[ARR_INDEX_ONE], asyncCallbackInfo->addFilter),
        "addFilter param error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_AddIptalbsFilterRule argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "AddIptablesFilterRule",
        NativeAddIptalbsFilterRule, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

bool NetworkManagerAddon::JsObjToAddFirewallObject(napi_env env, napi_value object, IPTABLES::AddFilter &filter)
{
    JsObjectToUint(env, object, "ruleNo", false, filter.ruleNo);
    JsObjectToString(env, object, "srcAddr", false, filter.srcAddr);
    JsObjectToString(env, object, "destAddr", false, filter.destAddr);
    JsObjectToString(env, object, "srcPort", false, filter.srcPort);
    JsObjectToString(env, object, "destPort", false, filter.destPort);
    JsObjectToString(env, object, "uid", false, filter.uid);
    int32_t method = -1;
    if (!JsObjectToInt(env, object, "method", true, method) ||
        !IPTABLES::IptablesUtils::ProcessFirewallMethod(method, filter.method)) {
        EDMLOGE("NAPI_AddIptalbsFilterRule JsObjToAddFirewallObject method trans failed");
        return false;
    }
    int32_t direction = -1;
    if (!JsObjectToInt(env, object, "direction", true, direction) ||
        !IPTABLES::IptablesUtils::ProcessFirewallDirection(direction, filter.direction)) {
        EDMLOGE("NAPI_AddIptalbsFilterRule JsObjToAddFirewallObject direction trans failed");
        return false;
    }
    int32_t action = -1;
    if (!JsObjectToInt(env, object, "action", true, action) ||
        !IPTABLES::IptablesUtils::ProcessFirewallAction(action, filter.action)) {
        EDMLOGE("NAPI_AddIptalbsFilterRule JsObjToAddFirewallObject action trans failed");
        return false;
    }
    int32_t protocol = -1;
    JsObjectToInt(env, object, "protocol", false, protocol);
    IPTABLES::IptablesUtils::ProcessFirewallProtocol(protocol, filter.protocol);
    return true;
}

void NetworkManagerAddon::NativeAddIptalbsFilterRule(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeAddIptalbsFilterRule called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncIptablesCallbackInfo *asyncCallbackInfo = static_cast<AsyncIptablesCallbackInfo *>(data);
    asyncCallbackInfo->ret = NetworkManagerProxy::GetNetworkManagerProxy()->AddIptablesFilterRule(
        asyncCallbackInfo->elementName, asyncCallbackInfo->addFilter);
}

napi_value NetworkManagerAddon::RemoveIptablesFilterRule(napi_env env, napi_callback_info info)
{
    EDMLOGI("NetworkManagerAddon::RemoveIptablesFilterRule called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncIptablesCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncIptablesCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "RemoveIptablesFilterRule: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ASSERT_AND_THROW_PARAM_ERROR(env,
        JsObjToRemoveFirewallObject(env, argv[ARR_INDEX_ONE], asyncCallbackInfo->removeFilter), "firewall param error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_RemoveIptablesFilterRule argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "RemoveIptablesFilterRule",
        NativeRemoveIptalbsFilterRule, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

bool NetworkManagerAddon::JsObjToRemoveFirewallObject(napi_env env, napi_value object, IPTABLES::RemoveFilter &firewall)
{
    JsObjectToString(env, object, "srcAddr", false, firewall.srcAddr);
    JsObjectToString(env, object, "destAddr", false, firewall.destAddr);
    JsObjectToString(env, object, "srcPort", false, firewall.srcPort);
    JsObjectToString(env, object, "destPort", false, firewall.destPort);
    JsObjectToString(env, object, "uid", false, firewall.uid);
    int32_t direction = -1;
    if (!JsObjectToInt(env, object, "direction", true, direction) ||
        !IPTABLES::IptablesUtils::ProcessFirewallDirection(direction, firewall.direction)) {
        EDMLOGE("NAPI_removeIptalbsFilterRule JsObjToRemoveFirewallObject direction trans failed");
        return false;
    }
    int32_t action = -1;
    JsObjectToInt(env, object, "action", false, action);
    IPTABLES::IptablesUtils::ProcessFirewallAction(action, firewall.action);
    int32_t protocol = -1;
    JsObjectToInt(env, object, "protocol", false, protocol);
    IPTABLES::IptablesUtils::ProcessFirewallProtocol(protocol, firewall.protocol);
    return true;
}

void NetworkManagerAddon::NativeRemoveIptalbsFilterRule(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeRemoveIptalbsFilterRule called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncIptablesCallbackInfo *asyncCallbackInfo = static_cast<AsyncIptablesCallbackInfo *>(data);
    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    asyncCallbackInfo->ret =
        networkManagerProxy->RemoveIptablesFilterRule(asyncCallbackInfo->elementName, asyncCallbackInfo->removeFilter);
}

napi_value NetworkManagerAddon::ListIptablesFilterRules(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    if (argc > ARGS_SIZE_ONE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARGS_SIZE_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncIptablesCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncIptablesCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "ListIptablesFilterRules: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("NAPI_ListIptablesFilterRule argc == ARGS_SIZE_TWO");
        napi_create_reference(env, argv[ARGS_SIZE_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "ListIptablesFilterRules",
        NativeListIptablesFilterRules, NativeStringCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void NetworkManagerAddon::NativeListIptablesFilterRules(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeListIptablesFilterRule called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncIptablesCallbackInfo *asyncCallbackInfo = static_cast<AsyncIptablesCallbackInfo *>(data);
    asyncCallbackInfo->ret = NetworkManagerProxy::GetNetworkManagerProxy()->ListIptablesFilterRules(
        asyncCallbackInfo->elementName, asyncCallbackInfo->stringRet);
}

napi_value NetworkManagerAddon::AddFirewallRule(napi_env env, napi_callback_info info)
{
    EDMLOGI("AddFirewallRule start");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasRule = MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasRule, "The second parameter must be FirewallRule.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    IPTABLES::FirewallRule rule = {IPTABLES::Direction::INVALID, IPTABLES::Action::INVALID,
        IPTABLES::Protocol::INVALID, "", "", "", "", ""};
    ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToFirewallRule(env, argv[ARR_INDEX_ONE], rule), "firewallRule param error");

    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->AddFirewallRule(elementName, rule);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value NetworkManagerAddon::RemoveFirewallRule(napi_env env, napi_callback_info info)
{
    EDMLOGI("RemoveFirewallRule start");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    if (argc >= ARGS_SIZE_TWO) {
        bool hasRule = MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
        ASSERT_AND_THROW_PARAM_ERROR(env, hasRule, "The second parameter must be FirewallRule.");
    }
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    IPTABLES::FirewallRule rule = {IPTABLES::Direction::INVALID, IPTABLES::Action::INVALID,
        IPTABLES::Protocol::INVALID, "", "", "", "", ""};
    if (argc >= ARGS_SIZE_TWO) {
        ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToFirewallRule(env, argv[ARR_INDEX_ONE], rule),
            "firewallRule param error");
    }
    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->RemoveFirewallRule(elementName, rule);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value NetworkManagerAddon::GetFirewallRules(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    std::vector<IPTABLES::FirewallRule> result;
    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->GetFirewallRules(elementName, result);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value jsList = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, result.size(), &jsList));
    for (size_t i = 0; i < result.size(); i++) {
        napi_value item = FirewallRuleToJsObj(env, result[i]);
        NAPI_CALL(env, napi_set_element(env, jsList, i, item));
    }
    return jsList;
}

bool NetworkManagerAddon::JsObjToFirewallRule(napi_env env, napi_value object, IPTABLES::FirewallRule &rule)
{
    int32_t direction = -1;
    JsObjectToInt(env, object, "direction", false, direction);
    EDMLOGI("JsObjToFirewallRule direction %{public}d", direction);
    IPTABLES::Direction directionEnum = IPTABLES::Direction::INVALID;
    IPTABLES::IptablesUtils::ProcessFirewallDirection(direction, directionEnum);

    int32_t action = -1;
    JsObjectToInt(env, object, "action", false, action);
    EDMLOGI("JsObjToFirewallRule action %{public}d", action);
    IPTABLES::Action actionEnum = IPTABLES::Action::INVALID;
    IPTABLES::IptablesUtils::ProcessFirewallAction(action, actionEnum);

    int32_t protocol = -1;
    JsObjectToInt(env, object, "protocol", false, protocol);
    EDMLOGI("JsObjToFirewallRule protocol %{public}d", protocol);
    IPTABLES::Protocol protocolEnum = IPTABLES::Protocol::INVALID;
    IPTABLES::IptablesUtils::ProcessFirewallProtocol(protocol, protocolEnum);

    std::string srcAddr;
    JsObjectToString(env, object, "srcAddr", false, srcAddr);

    std::string destAddr;
    JsObjectToString(env, object, "destAddr", false, destAddr);

    std::string srcPort;
    JsObjectToString(env, object, "srcPort", false, srcPort);

    std::string destPort;
    JsObjectToString(env, object, "destPort", false, destPort);

    std::string appUid;
    JsObjectToString(env, object, "appUid", false, appUid);
    rule = {directionEnum, actionEnum, protocolEnum, srcAddr, destAddr, srcPort, destPort, appUid};
    return true;
}

napi_value NetworkManagerAddon::FirewallRuleToJsObj(napi_env env, const IPTABLES::FirewallRule &rule)
{
    napi_value jsRule = nullptr;
    NAPI_CALL(env, napi_create_object(env, &jsRule));

    napi_value direction = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(std::get<FIREWALL_DICECTION_IND>(rule)), &direction));
    napi_value action = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(std::get<FIREWALL_ACTION_IND>(rule)), &action));
    napi_value protocol = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(std::get<FIREWALL_PROT_IND>(rule)), &protocol));
    napi_value srcAddr = nullptr;
    std::string srcAddrStr = std::get<FIREWALL_SRCADDR_IND>(rule);
    NAPI_CALL(env, napi_create_string_utf8(env, srcAddrStr.c_str(), srcAddrStr.length(), &srcAddr));
    napi_value destAddr = nullptr;
    std::string destAddrStr = std::get<FIREWALL_DESTADDR_IND>(rule);
    NAPI_CALL(env, napi_create_string_utf8(env, destAddrStr.c_str(), destAddrStr.length(), &destAddr));
    napi_value srcPort = nullptr;
    std::string srcPortStr = std::get<FIREWALL_SRCPORT_IND>(rule);
    NAPI_CALL(env, napi_create_string_utf8(env, srcPortStr.c_str(), srcPortStr.length(), &srcPort));
    napi_value destPort = nullptr;
    std::string destPortStr = std::get<FIREWALL_DESTPORT_IND>(rule);
    NAPI_CALL(env, napi_create_string_utf8(env, destPortStr.c_str(), destPortStr.length(), &destPort));
    napi_value appUid = nullptr;
    std::string appUidStr = std::get<FIREWALL_APPUID_IND>(rule);
    NAPI_CALL(env, napi_create_string_utf8(env, appUidStr.c_str(), appUidStr.length(), &appUid));

    NAPI_CALL(env, napi_set_named_property(env, jsRule, "direction", direction));
    NAPI_CALL(env, napi_set_named_property(env, jsRule, "action", action));
    NAPI_CALL(env, napi_set_named_property(env, jsRule, "protocol", protocol));
    NAPI_CALL(env, napi_set_named_property(env, jsRule, "srcAddr", srcAddr));
    NAPI_CALL(env, napi_set_named_property(env, jsRule, "destAddr", destAddr));
    NAPI_CALL(env, napi_set_named_property(env, jsRule, "srcPort", srcPort));
    NAPI_CALL(env, napi_set_named_property(env, jsRule, "destPort", destPort));
    NAPI_CALL(env, napi_set_named_property(env, jsRule, "appUid", appUid));
    return jsRule;
}

napi_value NetworkManagerAddon::AddDomainFilterRule(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasRule = MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasRule, "The second parameter must be DomainFilterRule.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    IPTABLES::DomainFilterRule rule = {IPTABLES::Action::INVALID, "", ""};
    ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToDomainFilterRule(env, argv[ARR_INDEX_ONE], rule),
        "DomainFilterRule param error");
    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->AddDomainFilterRule(elementName, rule);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value NetworkManagerAddon::RemoveDomainFilterRule(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    if (argc >= ARGS_SIZE_TWO) {
        bool hasRule = MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
        ASSERT_AND_THROW_PARAM_ERROR(env, hasRule, "The second parameter must be DomainFilterRule.");
    }

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    IPTABLES::DomainFilterRule rule = {IPTABLES::Action::INVALID, "", ""};
    if (argc >= ARGS_SIZE_TWO) {
        ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToDomainFilterRule(env, argv[ARR_INDEX_ONE], rule),
            "DomainFilterRule param error");
    }

    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->RemoveDomainFilterRule(elementName, rule);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value NetworkManagerAddon::GetDomainFilterRules(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    std::vector<IPTABLES::DomainFilterRule> result;
    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->GetDomainFilterRules(elementName, result);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value jsList = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, result.size(), &jsList));
    for (size_t i = 0; i < result.size(); i++) {
        napi_value item = DomainFilterRuleToJsObj(env, result[i]);
        NAPI_CALL(env, napi_set_element(env, jsList, i, item));
    }
    return jsList;
}

bool NetworkManagerAddon::JsObjToDomainFilterRule(napi_env env, napi_value object, IPTABLES::DomainFilterRule &rule)
{
    int32_t action = -1;
    JsObjectToInt(env, object, "action", false, action);
    IPTABLES::Action actionEnum = IPTABLES::Action::INVALID;
    IPTABLES::IptablesUtils::ProcessFirewallAction(action, actionEnum);

    std::string appUid;
    JsObjectToString(env, object, "appUid", false, appUid);

    std::string domainName;
    JsObjectToString(env, object, "domainName", false, domainName);

    rule = {actionEnum, appUid, domainName};
    return true;
}

napi_value NetworkManagerAddon::DomainFilterRuleToJsObj(napi_env env, const IPTABLES::DomainFilterRule &rule)
{
    napi_value jsRule = nullptr;
    NAPI_CALL(env, napi_create_object(env, &jsRule));

    napi_value action = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(std::get<DOMAIN_ACTION_IND>(rule)), &action));
    napi_value appUid = nullptr;
    std::string appUidStr = std::get<DOMAIN_APPUID_IND>(rule);
    NAPI_CALL(env, napi_create_string_utf8(env, appUidStr.c_str(), appUidStr.length(), &appUid));
    napi_value domainName = nullptr;
    std::string domainNameStr = std::get<DOMAIN_DOMAINNAME_IND>(rule);
    NAPI_CALL(env, napi_create_string_utf8(env, domainNameStr.c_str(), domainNameStr.length(), &domainName));

    NAPI_CALL(env, napi_set_named_property(env, jsRule, "action", action));
    NAPI_CALL(env, napi_set_named_property(env, jsRule, "appUid", appUid));
    NAPI_CALL(env, napi_set_named_property(env, jsRule, "domainName", domainName));
    return jsRule;
}

napi_value NetworkManagerAddon::SetGlobalHttpProxy(napi_env env, napi_callback_info info)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");

    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "parameter admin error");

    bool isHttpProxy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, isHttpProxy, "parameter http proxy error");

    if (argc > ARGS_SIZE_TWO) {
        bool hasCallback = MatchValueType(env, argv[ARGS_SIZE_TWO], napi_function);
        ASSERT_AND_THROW_PARAM_ERROR(env, hasCallback, "parameter callback error");
    }

    auto asyncCallbackInfo = new (std::nothrow) AsyncHttpProxyCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncHttpProxyCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "parameter element name error");
    bool parseRet = ParseHttpProxyParam(env, argv[ARR_INDEX_ONE], asyncCallbackInfo->httpProxy);
    ASSERT_AND_THROW_PARAM_ERROR(env, parseRet, "ParseHttpProxyParam error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_IsNetworkInterfaceDisabled argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "setGlobalProxy", NativeSetGlobalHttpProxy, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
#else
    EDMLOGW("NetworkManagerAddon::SetGlobalHttpProxy Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

#ifdef NETMANAGER_BASE_EDM_ENABLE
bool NetworkManagerAddon::ParseHttpProxyParam(napi_env env, napi_value argv, NetManagerStandard::HttpProxy &httpProxy)
{
    std::string host;
    if (!JsObjectToString(env, argv, HOST_PROP_NAME, true, host)) {
        EDMLOGE("error host value");
        return false;
    }
    std::int32_t port = 0;
    if (!JsObjectToInt(env, argv, PORT_PROP_NAME, true, port)) {
        EDMLOGE("error port value");
        return false;
    }
    OHOS::NetManagerStandard::SecureData username;
    if (!JsObjectToSecureData(env, argv, PROXY_USER_NAME, username)) {
        EDMLOGE("error username value");
        return false;
    }
    OHOS::NetManagerStandard::SecureData password;
    if (!JsObjectToSecureData(env, argv, PROXY_PASSWORD, password)) {
        EDMLOGE("error password value");
        return false;
    }
    if (!username.empty() && !password.empty()) {
        EDMLOGD("NetworkManagerAddon username and password is not empty.");
    } else {
        EDMLOGD("NetworkManagerAddon username or password is empty.");
    }
    std::vector<std::string> exclusionList;
    if (!JsObjectToStringVector(env, argv, EXCLUSION_LIST_PROP_NAME, true, exclusionList)) {
        EDMLOGE("error exclusionList value");
        return false;
    }

    httpProxy.SetHost(host.c_str());
    httpProxy.SetPort(port);
    httpProxy.SetUserName(username);
    httpProxy.SetPassword(password);
    std::list<std::string> dataList;
    for (const auto &item : exclusionList) {
        dataList.emplace_back(item);
    }
    httpProxy.SetExclusionList(dataList);
    return true;
}

bool NetworkManagerAddon::JsObjectToSecureData(napi_env env, napi_value object, const char *paramStr,
    OHOS::NetManagerStandard::SecureData &secureData)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, paramStr, &hasProperty) != napi_ok) {
        EDMLOGE("get js property failed.");
        return false;
    }
    if (hasProperty) {
        napi_value prop = nullptr;
        return napi_get_named_property(env, object, paramStr, &prop) == napi_ok &&
            ParseSecureData(env, secureData, prop);
    }
    return true;
}

bool NetworkManagerAddon::ParseSecureData(napi_env env, OHOS::NetManagerStandard::SecureData &secureData,
    napi_value object)
{
    napi_valuetype valuetype;
    if (napi_typeof(env, object, &valuetype) != napi_ok || valuetype != napi_string ||
        !GetSecureDataFromNAPI(env, object, secureData)) {
        EDMLOGE("can not get string value");
        return false;
    }
    return true;
}

bool NetworkManagerAddon::GetSecureDataFromNAPI(napi_env env, napi_value object,
    OHOS::NetManagerStandard::SecureData &secureData)
{
    OHOS::NetManagerStandard::SecureData result;
    size_t size = 0;

    if (napi_get_value_string_utf8(env, object, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        EDMLOGE("can not get string size");
        return false;
    }
    result.reserve(size + NAPI_RETURN_ONE);
    result.resize(size);
    if (napi_get_value_string_utf8(env, object, result.data(), (size + NAPI_RETURN_ONE), &size) != napi_ok) {
        EDMLOGE("can not get string value");
        return false;
    }
    secureData = result;
    return true;
}

void NetworkManagerAddon::NativeSetGlobalHttpProxy(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetGlobalHttpProxycalled");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncHttpProxyCallbackInfo *asyncCallbackInfo = static_cast<AsyncHttpProxyCallbackInfo *>(data);
    asyncCallbackInfo->ret = NetworkManagerProxy::GetNetworkManagerProxy()->SetGlobalHttpProxy(
        asyncCallbackInfo->elementName, asyncCallbackInfo->httpProxy);
}

napi_value NetworkManagerAddon::ConvertHttpProxyToJS(napi_env env, const OHOS::NetManagerStandard::HttpProxy &httpProxy)
{
    napi_value proxy = nullptr;
    NAPI_CALL(env, napi_create_object(env, &proxy));
    napi_value host = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, httpProxy.GetHost().c_str(), httpProxy.GetHost().length(), &host));
    napi_value port = nullptr;
    NAPI_CALL(env, napi_create_int32(env, httpProxy.GetPort(), &port));
    napi_value list = nullptr;
    if (httpProxy.GetExclusionList().empty()) {
        NAPI_CALL(env, napi_create_array(env, &list));
    } else {
        std::list<std::string> tempList = httpProxy.GetExclusionList();
        NAPI_CALL(env, napi_create_array_with_length(env, tempList.size(), &list));
        size_t index = 0;
        for (const auto &item : tempList) {
            napi_value ip = nullptr;
            NAPI_CALL(env, napi_create_string_utf8(env, item.c_str(), item.length(), &ip));
            NAPI_CALL(env, napi_set_element(env, list, index++, ip));
        }
    }
    NAPI_CALL(env, napi_set_named_property(env, proxy, HOST_PROP_NAME, host));
    NAPI_CALL(env, napi_set_named_property(env, proxy, PORT_PROP_NAME, port));
    NAPI_CALL(env, napi_set_named_property(env, proxy, EXCLUSION_LIST_PROP_NAME, list));
    return proxy;
}
#endif

napi_value NetworkManagerAddon::GetGlobalHttpProxy(napi_env env, napi_callback_info info)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncHttpProxyCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncHttpProxyCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool matchValue = false;
    if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_null)) {
        asyncCallbackInfo->hasAdmin = false;
        matchValue = true;
    } else if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object)) {
        asyncCallbackInfo->hasAdmin = true;
        matchValue = true;
    }
    if (argc > ARGS_SIZE_ONE) {
        matchValue = matchValue && MatchValueType(env, argv[ARGS_SIZE_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchValue, "parameter type error");
    if (asyncCallbackInfo->hasAdmin) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
            "element name param error");
        EDMLOGD(
            "GetGlobalHttpProxy: asyncCallbackInfo->elementName.bundlename %{public}s, "
            "asyncCallbackInfo->abilityname:%{public}s",
            asyncCallbackInfo->elementName.GetBundleName().c_str(),
            asyncCallbackInfo->elementName.GetAbilityName().c_str());
    }
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("NAPI_GetGlobalHttpProxy argc == ARGS_SIZE_TWO");
        napi_create_reference(env, argv[ARGS_SIZE_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "NativeGetGlobalHttpProxy",
        NativeGetGlobalHttpProxy, NativeHttpProxyCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
#else
    EDMLOGW("NetworkManagerAddon::GetGlobalHttpProxy Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

#ifdef NETMANAGER_BASE_EDM_ENABLE
void NetworkManagerAddon::NativeGetGlobalHttpProxy(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetGlobalHttpProxy called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncHttpProxyCallbackInfo *asyncCallbackInfo = static_cast<AsyncHttpProxyCallbackInfo *>(data);

    if (asyncCallbackInfo->hasAdmin) {
        asyncCallbackInfo->ret = NetworkManagerProxy::GetNetworkManagerProxy()->GetGlobalHttpProxy(
            &asyncCallbackInfo->elementName, asyncCallbackInfo->httpProxy);
    } else {
        asyncCallbackInfo->ret =
            NetworkManagerProxy::GetNetworkManagerProxy()->GetGlobalHttpProxy(nullptr, asyncCallbackInfo->httpProxy);
    }
}

void NetworkManagerAddon::NativeHttpProxyCallbackComplete(napi_env env, napi_status status, void *data)
{
    EDMLOGD("NativeHttpProxyCallbackComplete start");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncHttpProxyCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        EDMLOGD("asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_value jsHttpProxy = ConvertHttpProxyToJS(env, asyncCallbackInfo->httpProxy);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, jsHttpProxy);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
        }
    } else {
        napi_value callbackValue[ARGS_SIZE_TWO] = {0};
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &callbackValue[ARR_INDEX_ZERO]);
            callbackValue[ARR_INDEX_ONE] = ConvertHttpProxyToJS(env, asyncCallbackInfo->httpProxy);
        } else {
            callbackValue[ARR_INDEX_ZERO] = CreateError(env, asyncCallbackInfo->ret);
            napi_get_null(env, &callbackValue[ARR_INDEX_ONE]);
        }
        napi_value callback = nullptr;
        napi_value result = nullptr;
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_call_function(env, nullptr, callback, std::size(callbackValue), callbackValue, &result);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}
#endif

napi_value NetworkManagerAddon::GetAllNetworkInterfacesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAllNetworkInterfacesSync called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    EDMLOGD("GetAllNetworkInterfacesSync: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return nullptr;
    }
    std::vector<std::string> networkInterface;
    int32_t ret = networkManagerProxy->GetAllNetworkInterfaces(elementName, networkInterface, true);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_array(env, &result);
    ConvertStringVectorToJS(env, networkInterface, result);
    return result;
}

napi_value NetworkManagerAddon::GetIpAddressSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetIpAddressSync called");
    return GetIpOrMacAddressSync(env, info, EdmInterfaceCode::GET_IP_ADDRESS);
}

napi_value NetworkManagerAddon::GetMacSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetMacSync called");
    return GetIpOrMacAddressSync(env, info, EdmInterfaceCode::GET_MAC);
}

napi_value NetworkManagerAddon::GetIpOrMacAddressSync(napi_env env, napi_callback_info info, int policyCode)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string),
        "parameter networkInterface error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    std::string networkInterface;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, networkInterface, argv[ARR_INDEX_ONE]),
        "parameter networkInterface parse error");
    EDMLOGD("GetIpOrMacAddressSync: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return nullptr;
    }
    std::string ipOrMacInfo;
    int32_t ret = networkManagerProxy->GetIpOrMacAddress(elementName, networkInterface, policyCode, ipOrMacInfo, true);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_string_utf8(env, ipOrMacInfo.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value NetworkManagerAddon::SetNetworkInterfaceDisabledSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetNetworkInterfaceDisabledSync called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string),
        "parameter networkInterface error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean),
        "parameter isDisabled error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    std::string networkInterface;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, networkInterface, argv[ARR_INDEX_ONE]),
        "parameter networkInterface parse error");
    bool isDisabled = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, isDisabled, argv[ARR_INDEX_TWO]),
        "parameter isDisabled parse error");
    EDMLOGD("SetNetworkInterfaceDisabledSync: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return nullptr;
    }
    int32_t ret = networkManagerProxy->SetNetworkInterfaceDisabled(elementName, networkInterface, isDisabled, true);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return nullptr;
}

napi_value NetworkManagerAddon::IsNetworkInterfaceDisabledSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsNetworkInterfaceDisabledSync called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string),
        "parameter networkInterface error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    std::string networkInterface;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, networkInterface, argv[ARR_INDEX_ONE]),
        "parameter networkInterface parse error");
    EDMLOGD("IsNetworkInterfaceDisabledSync: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return nullptr;
    }
    bool isDisabled = false;
    int32_t ret = networkManagerProxy->IsNetworkInterfaceDisabled(elementName, networkInterface, isDisabled, true);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_boolean(env, isDisabled, &result);
    return result;
}

napi_value NetworkManagerAddon::SetGlobalHttpProxySync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetGlobalHttpProxySync called");
#ifdef NETMANAGER_BASE_EDM_ENABLE
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_object),
        "parameter httpProxy error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    NetManagerStandard::HttpProxy httpProxy;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseHttpProxyParam(env, argv[ARR_INDEX_ONE], httpProxy),
        "parameter httpProxy parse error");
    EDMLOGD("SetGlobalHttpProxySync: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return nullptr;
    }
    int32_t ret = networkManagerProxy->SetGlobalHttpProxy(elementName, httpProxy);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return nullptr;
#else
    EDMLOGW("NetworkManagerAddon::SetGlobalHttpProxy Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value NetworkManagerAddon::GetGlobalHttpProxySync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetGlobalHttpProxySync called");
#ifdef NETMANAGER_BASE_EDM_ENABLE
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    if (hasAdmin) {
        EDMLOGD("GetGlobalHttpProxySync: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
            elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    } else {
        EDMLOGD("GetGlobalHttpProxySync: elementName is null");
    }

    auto networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return nullptr;
    }
    NetManagerStandard::HttpProxy httpProxy;
    int32_t ret = ERR_OK;
    if (hasAdmin) {
        ret = networkManagerProxy->GetGlobalHttpProxy(&elementName, httpProxy);
    } else {
        ret = networkManagerProxy->GetGlobalHttpProxy(nullptr, httpProxy);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return ConvertHttpProxyToJS(env, httpProxy);
#else
    EDMLOGW("NetworkManagerAddon::GetGlobalHttpProxy Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

static napi_module g_networkManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = NetworkManagerAddon::Init,
    .nm_modname = "enterprise.networkManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void NetworkManagerRegister()
{
    napi_module_register(&g_networkManagerModule);
}