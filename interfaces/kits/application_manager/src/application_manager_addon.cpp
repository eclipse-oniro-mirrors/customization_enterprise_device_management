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

#include "application_manager_addon.h"
#include "edm_constants.h"
#include "edm_log.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_manager.h"
#endif

using namespace OHOS::EDM;

napi_value ApplicationManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("addDisallowedRunningBundles", AddDisallowedRunningBundles),
        DECLARE_NAPI_FUNCTION("removeDisallowedRunningBundles", RemoveDisallowedRunningBundles),
        DECLARE_NAPI_FUNCTION("getDisallowedRunningBundles", GetDisallowedRunningBundles),
        DECLARE_NAPI_FUNCTION("addAutoStartApps", AddAutoStartApps),
        DECLARE_NAPI_FUNCTION("removeAutoStartApps", RemoveAutoStartApps),
        DECLARE_NAPI_FUNCTION("getAutoStartApps", GetAutoStartApps),
        DECLARE_NAPI_FUNCTION("addDisallowedRunningBundlesSync", AddDisallowedRunningBundlesSync),
        DECLARE_NAPI_FUNCTION("removeDisallowedRunningBundlesSync", RemoveDisallowedRunningBundlesSync),
        DECLARE_NAPI_FUNCTION("getDisallowedRunningBundlesSync", GetDisallowedRunningBundlesSync),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value ApplicationManagerAddon::AddAutoStartApps(napi_env env, napi_callback_info info)
{
    return AddOrRemoveAutoStartApps(env, info, "AddAutoStartApps");
}

napi_value ApplicationManagerAddon::RemoveAutoStartApps(napi_env env, napi_callback_info info)
{
    return AddOrRemoveAutoStartApps(env, info, "RemoveAutoStartApps");
}

napi_value ApplicationManagerAddon::AddOrRemoveAutoStartApps(napi_env env, napi_callback_info info,
    std::string function)
{
    EDMLOGI("NAPI_AddOrRemoveAutoStartApps called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    std::vector<AppExecFwk::ElementName> autoStartApps;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementArray(env, autoStartApps, argv[ARR_INDEX_ONE]),
        "Parameter autoStartApps error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = 0;
    if (function == "AddAutoStartApps") {
        ret = applicationManagerProxy->AddAutoStartApps(elementName, autoStartApps);
    } else {
        ret = applicationManagerProxy->RemoveAutoStartApps(elementName, autoStartApps);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::GetAutoStartApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAutoStartApps called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    std::vector<OHOS::AppExecFwk::ElementName> autoStartApps;
    int32_t ret = applicationManagerProxy->GetAutoStartApps(elementName, autoStartApps);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiAutoStartApps = nullptr;
    napi_create_array(env, &napiAutoStartApps);
    size_t idx = 0;
    for (const auto &element : autoStartApps) {
        napi_value objAutoStartApps = nullptr;
        NAPI_CALL(env, napi_create_object(env, &objAutoStartApps));
        napi_value napi_bundleName;
        napi_value napi_abilityName;
        NAPI_CALL(env, napi_create_string_utf8(env, element.GetBundleName().c_str(),
            element.GetBundleName().size(), &napi_bundleName));
        NAPI_CALL(env, napi_create_string_utf8(env, element.GetAbilityName().c_str(),
            element.GetAbilityName().size(), &napi_abilityName));
        NAPI_CALL(env, napi_set_named_property(env, objAutoStartApps, "bundleName", napi_bundleName));
        NAPI_CALL(env, napi_set_named_property(env, objAutoStartApps, "abilityName", napi_abilityName));
        napi_set_element(env, napiAutoStartApps, idx, objAutoStartApps);
        idx++;
    }
    return napiAutoStartApps;
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
#ifdef OS_ACCOUNT_EDM_ENABLE
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
#endif
    }
    if (hasCallback) {
        ASSERT_AND_THROW_PARAM_ERROR(env,
            ParseCallback(env, asyncCallbackInfo->callback,
                argc <= ARR_INDEX_THREE ? argv[argc - 1] : argv[ARR_INDEX_TWO]),
            "Parameter callback error");
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
#ifdef OS_ACCOUNT_EDM_ENABLE
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
#endif
    }
    if (hasCallback) {
        ASSERT_AND_THROW_PARAM_ERROR(env,
            ParseCallback(env, asyncCallbackInfo->callback,
                argc <= ARR_INDEX_FOUR ? argv[argc - 1] : argv[ARR_INDEX_THREE]),
            "Parameter callback error");
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

napi_value ApplicationManagerAddon::AddDisallowedRunningBundlesSync(napi_env env, napi_callback_info info)
{
    return AddOrRemoveDisallowedRunningBundlesSync(env, info, true);
}

napi_value ApplicationManagerAddon::RemoveDisallowedRunningBundlesSync(napi_env env, napi_callback_info info)
{
    return AddOrRemoveDisallowedRunningBundlesSync(env, info, false);
}

napi_value ApplicationManagerAddon::AddOrRemoveDisallowedRunningBundlesSync(napi_env env, napi_callback_info info,
    bool isAdd)
{
    EDMLOGI("NAPI_AddOrRemoveDisallowedRunningBundlesSync called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    bool hasAccountId = (argc == ARGS_SIZE_THREE);
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_object), "parameter appIds error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    std::vector<std::string> appIds;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, appIds, argv[ARR_INDEX_ONE]),
        "parameter appIds parse error");
    EDMLOGD("AddOrRemoveDisallowedRunningBundlesSync: "
        "elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    int32_t accountId = 0;
    if (hasAccountId) {
        ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_number),
            "parameter accountId error");
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_TWO]),
            "parameter accountId parse error");
    } else {
#ifdef OS_ACCOUNT_EDM_ENABLE
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(accountId);
#endif
    }

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    if (applicationManagerProxy == nullptr) {
        EDMLOGE("can not get applicationManagerProxy");
        return nullptr;
    }
    int32_t ret = ERR_OK;
    if (isAdd) {
        ret = applicationManagerProxy->AddDisallowedRunningBundles(elementName, appIds, accountId, true);
    } else {
        ret = applicationManagerProxy->RemoveDisallowedRunningBundles(elementName, appIds, accountId, true);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::GetDisallowedRunningBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedRunningBundlesSync called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAccountId = (argc == ARGS_SIZE_TWO);
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    EDMLOGD("GetDisallowedRunningBundlesSync: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    int32_t accountId = 0;
    if (hasAccountId) {
        ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_number),
            "parameter accountId error");
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_ONE]),
            "parameter accountId parse error");
    } else {
#ifdef OS_ACCOUNT_EDM_ENABLE
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(accountId);
#endif
    }

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    if (applicationManagerProxy == nullptr) {
        EDMLOGE("can not get applicationManagerProxy");
        return nullptr;
    }
    std::vector<std::string> appIds;
    int32_t ret = applicationManagerProxy->GetDisallowedRunningBundles(elementName, accountId, appIds, true);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_array(env, &result);
    ConvertStringVectorToJS(env, appIds, result);
    return result;
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