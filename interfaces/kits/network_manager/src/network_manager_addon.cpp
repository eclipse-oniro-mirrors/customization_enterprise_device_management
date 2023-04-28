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
#include "network_manager_addon.h"
#include "edm_log.h"
#include "napi_edm_common.h"
#include "policy_info.h"

using namespace OHOS::EDM;

napi_value NetworkManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("getAllNetworkInterfaces", GetAllNetworkInterfaces),
        DECLARE_NAPI_FUNCTION("getIpAddress", GetIpAddress),
        DECLARE_NAPI_FUNCTION("getMac", GetMac),
        DECLARE_NAPI_FUNCTION("setNetworkInterfaceDisabled", SetNetworkInterfaceDisabled),
        DECLARE_NAPI_FUNCTION("isNetworkInterfaceDisabled", IsNetworkInterfaceDisabled),
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
    std::unique_ptr<AsyncNetworkInterfacesCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("GetAllNetworkInterfaces: asyncCallbackInfo->elementName.bundlename %{public}s, "
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
    auto networkManagerProxy_ = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy_ == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = networkManagerProxy_->GetAllNetworkInterfaces(asyncCallbackInfo->elementName,
        asyncCallbackInfo->arrayStringRet);
}

napi_value NetworkManagerAddon::GetIpAddress(napi_env env, napi_callback_info info)
{
    EDMLOGI("NetworkManagerAddon::GetIpAddress called");
    return GetIpOrMacAddress(env, info, GET_IP_ADDRESS);
}

napi_value NetworkManagerAddon::GetMac(napi_env env, napi_callback_info info)
{
    EDMLOGI("NetworkManagerAddon::GetMac called");
    return GetIpOrMacAddress(env, info, GET_MAC);
}

napi_value NetworkManagerAddon::GetIpOrMacAddress(napi_env env, napi_callback_info info, int policyCode)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_string);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARGS_SIZE_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncNetworkInfoCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncNetworkInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->networkInterface, argv[ARR_INDEX_ONE]),
        "parameter networkInterface error");
    EDMLOGD("GetIpOrMacAddress: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_GetIpOrMacAddress argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    asyncCallbackInfo->policyCode = policyCode;
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "GetIpAddress",
        NativeGetIpOrMacAddress, NativeStringCallbackComplete);
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
    auto networkManagerProxy_ = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy_ == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = networkManagerProxy_->GetIpOrMacAddress(asyncCallbackInfo->elementName,
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
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_string) &&
        MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean);
    if (argc > ARGS_SIZE_THREE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARGS_SIZE_THREE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncSetNetworkInterfaceCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSetNetworkInterfaceCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "parameter element name error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->networkInterface, argv[ARR_INDEX_ONE]),
        "parameter networkInterface error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, asyncCallbackInfo->isDisabled, argv[ARR_INDEX_TWO]),
        "parameter isDisabled error");
    EDMLOGD("SetNetworkInterfaceDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
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
    auto networkManagerProxy_ = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy_ == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = networkManagerProxy_->SetNetworkInterfaceDisabled(asyncCallbackInfo->elementName,
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
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_string);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARGS_SIZE_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncNetworkInfoCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncNetworkInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "parameter element name error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->networkInterface, argv[ARR_INDEX_ONE]),
        "parameter networkInterface error");
    EDMLOGD("IsNetworkInterfaceDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
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
    auto networkManagerProxy_ = NetworkManagerProxy::GetNetworkManagerProxy();
    if (networkManagerProxy_ == nullptr) {
        EDMLOGE("can not get GetNetworkManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = networkManagerProxy_->IsNetworkInterfaceDisabled(asyncCallbackInfo->elementName,
        asyncCallbackInfo->networkInterface, asyncCallbackInfo->boolRet);
}

static napi_module g_networkManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = NetworkManagerAddon::Init,
    .nm_modname = "enterprise.networkManager",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void NetworkManagerRegister()
{
    napi_module_register(&g_networkManagerModule);
}