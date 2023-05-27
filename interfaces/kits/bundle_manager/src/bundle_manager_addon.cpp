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

#include "bundle_manager_addon.h"
#include <unordered_map>
#include "edm_constants.h"
#include "edm_log.h"
#include "os_account_manager.h"
#include "policy_type.h"

using namespace OHOS::EDM;

static const std::unordered_map<std::string, int32_t> POLICY_TYPE_MAP = {
    {"AddAllowedInstallBundles", static_cast<int32_t>(PolicyType::ALLOW_INSTALL)},
    {"AddDisallowedInstallBundles", static_cast<int32_t>(PolicyType::DISALLOW_INSTALL)},
    {"AddDisallowedUninstallBundles", static_cast<int32_t>(PolicyType::DISALLOW_UNINSTALL)},
    {"RemoveAllowedInstallBundles", static_cast<int32_t>(PolicyType::ALLOW_INSTALL)},
    {"RemoveDisallowedInstallBundles", static_cast<int32_t>(PolicyType::DISALLOW_INSTALL)},
    {"RemoveDisallowedUninstallBundles", static_cast<int32_t>(PolicyType::DISALLOW_UNINSTALL)},
    {"GetAllowedInstallBundles", static_cast<int32_t>(PolicyType::ALLOW_INSTALL)},
    {"GetDisallowedInstallBundles", static_cast<int32_t>(PolicyType::DISALLOW_INSTALL)},
    {"GetDisallowedUninstallBundles", static_cast<int32_t>(PolicyType::DISALLOW_UNINSTALL)},
};

napi_value BundleManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("addAllowedInstallBundles", AddAllowedInstallBundles),
        DECLARE_NAPI_FUNCTION("removeAllowedInstallBundles", RemoveAllowedInstallBundles),
        DECLARE_NAPI_FUNCTION("getAllowedInstallBundles", GetAllowedInstallBundles),
        DECLARE_NAPI_FUNCTION("addDisallowedInstallBundles", AddDisallowedInstallBundles),
        DECLARE_NAPI_FUNCTION("removeDisallowedInstallBundles", RemoveDisallowedInstallBundles),
        DECLARE_NAPI_FUNCTION("getDisallowedInstallBundles", GetDisallowedInstallBundles),
        DECLARE_NAPI_FUNCTION("addDisallowedUninstallBundles", AddDisallowedUninstallBundles),
        DECLARE_NAPI_FUNCTION("removeDisallowedUninstallBundles", RemoveDisallowedUninstallBundles),
        DECLARE_NAPI_FUNCTION("getDisallowedUninstallBundles", GetDisallowedUninstallBundles),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value BundleManagerAddon::GetAllowedInstallBundles(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAllowedInstallBundles called");
    return GetAllowedOrDisallowedInstallBundles(env, info, "GetAllowedInstallBundles", NativeGetBundlesByPolicyType);
}

napi_value BundleManagerAddon::GetDisallowedInstallBundles(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedInstallBundles called");
    return GetAllowedOrDisallowedInstallBundles(env, info, "GetDisallowedInstallBundles", NativeGetBundlesByPolicyType);
}

napi_value BundleManagerAddon::GetDisallowedUninstallBundles(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedUninstallBundles called");
    return GetAllowedOrDisallowedInstallBundles(env, info, "GetDisallowedUninstallBundles",
        NativeGetBundlesByPolicyType);
}

napi_value BundleManagerAddon::GetAllowedOrDisallowedInstallBundles(napi_env env, napi_callback_info info,
    const std::string &workName, napi_async_execute_callback execute)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    bool hasCallback = false;
    bool hasUserId = false;
    auto asyncCallbackInfo = new (std::nothrow) AsyncBundlesCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncBundlesCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckAdminWithUserIdParamType(env, argc, argv, hasCallback, hasUserId),
        "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");

    EDMLOGD("GetInstallBundles bundlename %{public}s, abilityname:%{public}s",
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
    InitCallbackInfoPolicyType(workName, asyncCallbackInfo);
    EDMLOGI("GetInstallBundles::%{public}s policyType = %{public}d", workName.c_str(), asyncCallbackInfo->policyType);
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, workName,
        execute, NativeArrayStringCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void BundleManagerAddon::InitCallbackInfoPolicyType(const std::string &workName, AsyncBundlesCallbackInfo *callbackInfo)
{
    auto iter = POLICY_TYPE_MAP.find(workName);
    if (iter != POLICY_TYPE_MAP.end()) {
        callbackInfo->policyType = iter->second;
    } else {
        EDMLOGI("policy type map get error");
        callbackInfo->policyType = static_cast<int32_t>(PolicyType::INVALID_TYPE);
    }
}

void BundleManagerAddon::NativeGetBundlesByPolicyType(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetBundlesByPolicyType called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncBundlesCallbackInfo *asyncCallbackInfo = static_cast<AsyncBundlesCallbackInfo *>(data);
    auto proxy = BundleManagerProxy::GetBundleManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get BundleManagerProxy");
        return;
    }

    asyncCallbackInfo->ret = proxy->GetBundlesByPolicyType(asyncCallbackInfo->elementName,
        asyncCallbackInfo->userId, asyncCallbackInfo->arrayStringRet, asyncCallbackInfo->policyType);
}

napi_value BundleManagerAddon::AddAllowedInstallBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemoveInstallBundles(env, info, "AddAllowedInstallBundles", NativeAddBundlesByPolicyType);
}

napi_value BundleManagerAddon::AddDisallowedInstallBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemoveInstallBundles(env, info, "AddDisallowedInstallBundles", NativeAddBundlesByPolicyType);
}

napi_value BundleManagerAddon::AddDisallowedUninstallBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemoveInstallBundles(env, info, "AddDisallowedUninstallBundles", NativeAddBundlesByPolicyType);
}

napi_value BundleManagerAddon::RemoveAllowedInstallBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemoveInstallBundles(env, info, "RemoveAllowedInstallBundles", NativeRemoveBundlesByPolicyType);
}

napi_value BundleManagerAddon::RemoveDisallowedInstallBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemoveInstallBundles(env, info, "RemoveDisallowedInstallBundles", NativeRemoveBundlesByPolicyType);
}

napi_value BundleManagerAddon::RemoveDisallowedUninstallBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemoveInstallBundles(env, info, "RemoveDisallowedUninstallBundles", NativeRemoveBundlesByPolicyType);
}

bool BundleManagerAddon::CheckAddInstallBundlesParamType(napi_env env, size_t argc,
    napi_value* argv, bool &hasCallback, bool &hasUserId)
{
    if (!MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) || !MatchValueType(env, argv[ARR_INDEX_ONE],
        napi_object)) {
        EDMLOGE("CheckAddInstallBundlesParamType admin or array type check failed");
        return false;
    }
    EDMLOGI("CheckAddInstallBundlesParamType argc = %{public}zu", argc);
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

napi_value BundleManagerAddon::AddOrRemoveInstallBundles(napi_env env, napi_callback_info info,
    const std::string &workName, napi_async_execute_callback execute)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    bool hasCallback = false;
    bool hasUserId = false;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    auto asyncCallbackInfo = new (std::nothrow) AsyncBundlesCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncBundlesCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckAddInstallBundlesParamType(env, argc, argv, hasCallback, hasUserId),
        "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, asyncCallbackInfo->bundles, argv[ARR_INDEX_ONE]),
        "Parameter bundles error");
    ASSERT_AND_THROW_PARAM_ERROR(env, asyncCallbackInfo->bundles.size() <= EdmConstants::APPID_MAX_SIZE,
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
    InitCallbackInfoPolicyType(workName, asyncCallbackInfo);
    EDMLOGI("AddOrRemoveInstallBundles::%{public}s policyType = %{public}d", workName.c_str(),
        asyncCallbackInfo->policyType);
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, workName, execute, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void BundleManagerAddon::NativeRemoveBundlesByPolicyType(napi_env env, void *data)
{
    EDMLOGI("NativeRemoveBundlesByPolicyType called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncBundlesCallbackInfo *asyncCallbackInfo = static_cast<AsyncBundlesCallbackInfo *>(data);
    auto bundleManagerProxy = BundleManagerProxy::GetBundleManagerProxy();
    if (bundleManagerProxy == nullptr) {
        EDMLOGE("can not get BundleManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = bundleManagerProxy->RemoveBundlesByPolicyType(asyncCallbackInfo->elementName,
        asyncCallbackInfo->bundles, asyncCallbackInfo->userId, asyncCallbackInfo->policyType);
}

void BundleManagerAddon::NativeAddBundlesByPolicyType(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeAddBundlesByPolicyType called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncBundlesCallbackInfo *asyncCallbackInfo = static_cast<AsyncBundlesCallbackInfo *>(data);
    auto bundleManagerProxy = BundleManagerProxy::GetBundleManagerProxy();
    if (bundleManagerProxy == nullptr) {
        EDMLOGE("can not get BundleManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = bundleManagerProxy->AddBundlesByPolicyType(asyncCallbackInfo->elementName,
        asyncCallbackInfo->bundles, asyncCallbackInfo->userId, asyncCallbackInfo->policyType);
}

static napi_module g_bundleManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BundleManagerAddon::Init,
    .nm_modname = "enterprise.bundleManager",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void BundleManagerRegister()
{
    napi_module_register(&g_bundleManagerModule);
}