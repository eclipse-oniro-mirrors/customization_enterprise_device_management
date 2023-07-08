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

#include "browser_addon.h"

#include "browser_proxy.h"
#include "edm_constants.h"
#include "edm_log.h"

using namespace OHOS::EDM;

napi_value BrowserAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setPolicies", SetPolicies),
        DECLARE_NAPI_FUNCTION("getPolicies", GetPolicies),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value BrowserAddon::SetPolicies(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetPolicies called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "Parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_string) && MatchValueType(env, argv[ARR_INDEX_TWO], napi_string);
    if (argc > ARGS_SIZE_THREE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARGS_SIZE_THREE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncBrowserCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncBrowserCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->appId, argv[ARR_INDEX_ONE]),
        "Parameter policies error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->policies, argv[ARR_INDEX_TWO]),
        "Parameter policies error");
    EDMLOGD(
        "EnableAdmin::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_THREE) {
        napi_create_reference(env, argv[ARGS_SIZE_THREE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "setPolicies", NativeSetPolicies, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void BrowserAddon::NativeSetPolicies(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetPolicies called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncBrowserCallbackInfo *asyncCallbackInfo = static_cast<AsyncBrowserCallbackInfo *>(data);
    asyncCallbackInfo->ret = BrowserProxy::GetBrowserProxy()->SetPolicies(asyncCallbackInfo->elementName,
        asyncCallbackInfo->appId, asyncCallbackInfo->policies);
}

napi_value BrowserAddon::GetPolicies(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "admin type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "appId type error");
    if (argc > ARGS_SIZE_TWO) {
        ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_function),
            "callback type error");
    }

    auto asyncCallbackInfo = new (std::nothrow) AsyncBrowserCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncBrowserCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->appId, argv[ARR_INDEX_ONE]),
        "Parameter appId error");
    EDMLOGD(
        "EnableAdmin::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_TWO) {
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "getPolicies", NativeGetPolicies, NativeStringCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void BrowserAddon::NativeGetPolicies(napi_env env, void *data)
{
    EDMLOGI("NativeGetPolicies called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncBrowserCallbackInfo *asyncCallbackInfo = static_cast<AsyncBrowserCallbackInfo *>(data);
    asyncCallbackInfo->ret = BrowserProxy::GetBrowserProxy()->GetPolicies(asyncCallbackInfo->elementName,
        asyncCallbackInfo->appId, asyncCallbackInfo->stringRet);
}

static napi_module g_browserModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BrowserAddon::Init,
    .nm_modname = "enterprise.browser",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void BrowserRegister()
{
    napi_module_register(&g_browserModule);
}