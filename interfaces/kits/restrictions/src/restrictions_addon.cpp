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

#include "restrictions_addon.h"

#include "edm_ipc_interface_code.h"
#include "edm_log.h"

using namespace OHOS::EDM;

std::map<int, RestrictionsAddon::RestrictionsProxySetFunc> RestrictionsAddon::memberSetFuncMap_ = {
    {EdmInterfaceCode::DISABLED_PRINTER, &RestrictionsProxy::SetPrinterDisabled},
    {EdmInterfaceCode::DISABLED_HDC, &RestrictionsProxy::SetHdcDisabled},
};

std::map<int, RestrictionsAddon::RestrictionsProxyIsFunc> RestrictionsAddon::memberIsFuncMap_ = {
    {EdmInterfaceCode::DISABLED_PRINTER, &RestrictionsProxy::IsPrinterDisabled},
    {EdmInterfaceCode::DISABLED_HDC, &RestrictionsProxy::IsHdcDisabled},
};

napi_value RestrictionsAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setPrinterDisabled", SetPrinterDisabled),
        DECLARE_NAPI_FUNCTION("isPrinterDisabled", IsPrinterDisabled),
        DECLARE_NAPI_FUNCTION("setHdcDisabled", SetHdcDisabled),
        DECLARE_NAPI_FUNCTION("isHdcDisabled", IsHdcDisabled),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value RestrictionsAddon::SetPrinterDisabled(napi_env env, napi_callback_info info)
{
    return SetPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_PRINTER);
}

napi_value RestrictionsAddon::SetHdcDisabled(napi_env env, napi_callback_info info)
{
    return SetPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_HDC);
}

napi_value RestrictionsAddon::SetPolicyDisabled(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_SetPolicyDisabled called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_boolean);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasPolicy, "The second parameter must be bool.");
    if (argc > ARGS_SIZE_TWO) {
        bool hasCallback = MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
        ASSERT_AND_THROW_PARAM_ERROR(env, hasCallback, "The third parameter must be function");
    }
    auto asyncCallbackInfo = new (std::nothrow) AsyncRestrictionsCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncRestrictionsCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD(
        "SetPolicyDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ret = ParseBool(env, asyncCallbackInfo->isDisabled, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "isDisabled param error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_SetPolicyDisabled argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARR_INDEX_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    asyncCallbackInfo->policyCode = policyCode;
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "SetPolicyDisabled", NativeSetPolicyDisabled,
        NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void RestrictionsAddon::NativeSetPolicyDisabled(napi_env env, void *data)
{
    EDMLOGI("NativeSetPolicyDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncRestrictionsCallbackInfo *asyncCallbackInfo = static_cast<AsyncRestrictionsCallbackInfo *>(data);
    auto func = memberSetFuncMap_.find(asyncCallbackInfo->policyCode);
    if (func != memberSetFuncMap_.end()) {
        auto memberFunc = func->second;
        auto proxy = RestrictionsProxy::GetRestrictionsProxy();
        asyncCallbackInfo->ret =
            (proxy.get()->*memberFunc)(asyncCallbackInfo->elementName, asyncCallbackInfo->isDisabled);
    } else {
        EDMLOGE("NativeSetPolicyDisabled failed");
        asyncCallbackInfo->ret = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
}

napi_value RestrictionsAddon::IsPrinterDisabled(napi_env env, napi_callback_info info)
{
    return IsPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_PRINTER);
}

napi_value RestrictionsAddon::IsHdcDisabled(napi_env env, napi_callback_info info)
{
    return IsPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_HDC);
}

napi_value RestrictionsAddon::IsPolicyDisabled(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_IsPolicyDisabled called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncRestrictionsCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncRestrictionsCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool matchFlag = false;
    if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_null)) {
        asyncCallbackInfo->hasAdmin = false;
        matchFlag = true;
    } else if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object)) {
        matchFlag = true;
        asyncCallbackInfo->hasAdmin = true;
        bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
        ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
        EDMLOGD(
            "IsPolicyDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
            "asyncCallbackInfo->abilityname:%{public}s",
            asyncCallbackInfo->elementName.GetBundleName().c_str(),
            asyncCallbackInfo->elementName.GetAbilityName().c_str());
    }
    if (argc > ARGS_SIZE_ONE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("NAPI_IsPolicyDisabled argc == ARGS_SIZE_TWO");
        napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    asyncCallbackInfo->policyCode = policyCode;
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "IsPolicyDisabled", NativeIsPolicyDisabled, NativeBoolCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void RestrictionsAddon::NativeIsPolicyDisabled(napi_env env, void *data)
{
    EDMLOGI("NativeIsPolicyDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncRestrictionsCallbackInfo *asyncCallbackInfo = static_cast<AsyncRestrictionsCallbackInfo *>(data);
    auto func = memberIsFuncMap_.find(asyncCallbackInfo->policyCode);
    if (func != memberIsFuncMap_.end()) {
        auto memberFunc = func->second;
        auto proxy = RestrictionsProxy::GetRestrictionsProxy();
        if (asyncCallbackInfo->hasAdmin) {
            asyncCallbackInfo->ret =
                (proxy.get()->*memberFunc)(&(asyncCallbackInfo->elementName), asyncCallbackInfo->boolRet);
        } else {
            asyncCallbackInfo->ret = (proxy.get()->*memberFunc)(nullptr, asyncCallbackInfo->boolRet);
        }
    } else {
        EDMLOGE("NativeIsPolicyDisabled error");
        asyncCallbackInfo->ret = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
}

static napi_module g_restrictionsModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = RestrictionsAddon::Init,
    .nm_modname = "enterprise.restrictions",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RestrictionsRegister()
{
    napi_module_register(&g_restrictionsModule);
}