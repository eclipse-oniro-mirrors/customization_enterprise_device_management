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

#include "application_manager_addon.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "os_account_manager.h"

using namespace OHOS::EDM;

napi_value ApplicationManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("addDisallowedRunningBundles", AddDisallowedRunningBundles),
        DECLARE_NAPI_FUNCTION("removeDisallowedRunningBundles", RemoveDisallowedRunningBundles),
        DECLARE_NAPI_FUNCTION("getDisallowedRunningBundles", GetDisallowedRunningBundles),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value ApplicationManagerAddon::GetDisallowedRunningBundles(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedRunningBundles called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    bool hasCallback = false;
    bool hasUserId = false;
    auto asyncCallbackInfo = new (std::nothrow) AsyncDisallowedRunningBundlesCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncDisallowedRunningBundlesCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckAdminWithUserIdParamType(env, argc, argv, hasCallback, hasUserId),
        "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");

    EDMLOGD("GetDisallowedRunningBundles::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (hasUserId) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->userId, argv[ARR_INDEX_ONE]),
            "Parameter user id error");
    } else {
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
    }
    if (hasCallback) {
        napi_create_reference(env, argv[argc - 1], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "GetDisallowedRunningBundles",
        NativeGetDisallowedRunningBundles, NativeArrayStringCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void ApplicationManagerAddon::NativeGetDisallowedRunningBundles(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetDisallowedRunningBundles called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncDisallowedRunningBundlesCallbackInfo *asyncCallbackInfo =
        static_cast<AsyncDisallowedRunningBundlesCallbackInfo *>(data);
    auto proxy_ = ApplicationManagerProxy::GetApplicationManagerProxy();
    if (proxy_ == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }

    asyncCallbackInfo->ret = proxy_->GetDisallowedRunningBundles(asyncCallbackInfo->elementName,
        asyncCallbackInfo->userId, asyncCallbackInfo->arrayStringRet);
}

napi_value ApplicationManagerAddon::AddDisallowedRunningBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemovellowedRunningBundles(env, info, "AddDisallowedRunningBundles", NativeAddDisallowedRunningBundles);
}

napi_value ApplicationManagerAddon::RemoveDisallowedRunningBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemovellowedRunningBundles(env, info, "RemoveDisallowedRunningBundles",
        NativeRemoveDisallowedRunningBundles);
}

void ApplicationManagerAddon::NativeAddDisallowedRunningBundles(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeAddDisallowedRunningBundles called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncDisallowedRunningBundlesCallbackInfo *asyncCallbackInfo =
        static_cast<AsyncDisallowedRunningBundlesCallbackInfo *>(data);
    auto applicationManagerProxy_ = ApplicationManagerProxy::GetApplicationManagerProxy();
    if (applicationManagerProxy_ == nullptr) {
        EDMLOGE("can not get applicationManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = applicationManagerProxy_->AddDisallowedRunningBundles(asyncCallbackInfo->elementName,
        asyncCallbackInfo->appIds, asyncCallbackInfo->userId);
}

bool ApplicationManagerAddon::CheckAddDisallowedRunningBundlesParamType(napi_env env, size_t argc,
    napi_value* argv, bool &hasCallback, bool &hasUserId)
{
    if (!MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) || !MatchValueType(env, argv[ARR_INDEX_ONE],
        napi_object)) {
        EDMLOGE("CheckAddDisallowedRunningBundlesParamType admin or array type check failed");
        return false;
    }
    EDMLOGI("CheckAddDisallowedRunningBundlesParamType argc = %{public}zu", argc);
    if (argc == ARGS_SIZE_TWO) {
        hasCallback = false;
        hasUserId = false;
        EDMLOGI("hasCallback = false; hasUserId = false;");
        return true;
    }

    if (argc == ARGS_SIZE_THREE) {
        if (MatchValueType(env, argv[ARR_INDEX_TWO], napi_function)) {
            hasCallback = true;
            hasUserId = false;
            EDMLOGI("hasCallback = true; hasUserId = false;");
            return true;
        } else {
            hasCallback = false;
            hasUserId = true;
            EDMLOGI("hasCallback = false;  hasUserId = true;");
            return MatchValueType(env, argv[ARR_INDEX_TWO], napi_number);
        }
    }
    hasCallback = true;
    hasUserId = true;
    EDMLOGI("hasCallback = true; hasUserId = true;");
    return MatchValueType(env, argv[ARR_INDEX_TWO], napi_number) &&
        MatchValueType(env, argv[ARR_INDEX_THREE], napi_function);
}

napi_value ApplicationManagerAddon::AddOrRemovellowedRunningBundles(napi_env env, napi_callback_info info,
    const std::string &workName, napi_async_execute_callback execute)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    bool hasCallback = false;
    bool hasUserId = false;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    auto asyncCallbackInfo = new (std::nothrow) AsyncDisallowedRunningBundlesCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncDisallowedRunningBundlesCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env,
        CheckAddDisallowedRunningBundlesParamType(env, argc, argv, hasCallback, hasUserId), "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, asyncCallbackInfo->appIds, argv[ARR_INDEX_ONE]),
        "Parameter bundles error");
    ASSERT_AND_THROW_PARAM_ERROR(env, asyncCallbackInfo->appIds.size() <= EdmConstants::APPID_MAX_SIZE,
        "Parameter bundles too large");
    EDMLOGD("EnableAdmin::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (hasUserId) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->userId, argv[ARR_INDEX_TWO]),
            "Parameter user id error");
    } else {
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
    }
    if (hasCallback) {
        napi_create_reference(env, argv[argc - 1], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, workName,
        execute, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void ApplicationManagerAddon::NativeRemoveDisallowedRunningBundles(napi_env env, void *data)
{
    EDMLOGI("NativeRemoveDisallowedRunningBundles called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncDisallowedRunningBundlesCallbackInfo *asyncCallbackInfo =
        static_cast<AsyncDisallowedRunningBundlesCallbackInfo *>(data);
    auto applicationManagerProxy_ = ApplicationManagerProxy::GetApplicationManagerProxy();
    if (applicationManagerProxy_ == nullptr) {
        EDMLOGE("can not get ApplicationManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = applicationManagerProxy_->RemoveDisallowedRunningBundles(asyncCallbackInfo->elementName,
        asyncCallbackInfo->appIds, asyncCallbackInfo->userId);
}

static napi_module g_applicationManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = ApplicationManagerAddon::Init,
    .nm_modname = "enterprise.applicationManager",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void ApplicationManagerRegister()
{
    napi_module_register(&g_applicationManagerModule);
}