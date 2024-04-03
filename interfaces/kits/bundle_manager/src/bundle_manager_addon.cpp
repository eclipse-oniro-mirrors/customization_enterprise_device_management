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
        DECLARE_NAPI_FUNCTION("uninstall", Uninstall),
        DECLARE_NAPI_FUNCTION("install", Install),
        DECLARE_NAPI_FUNCTION("addAllowedInstallBundlesSync", AddAllowedInstallBundlesSync),
        DECLARE_NAPI_FUNCTION("removeAllowedInstallBundlesSync", RemoveAllowedInstallBundlesSync),
        DECLARE_NAPI_FUNCTION("getAllowedInstallBundlesSync", GetAllowedInstallBundlesSync),
        DECLARE_NAPI_FUNCTION("addDisallowedInstallBundlesSync", AddDisallowedInstallBundlesSync),
        DECLARE_NAPI_FUNCTION("removeDisallowedInstallBundlesSync", RemoveDisallowedInstallBundlesSync),
        DECLARE_NAPI_FUNCTION("getDisallowedInstallBundlesSync", GetDisallowedInstallBundlesSync),
        DECLARE_NAPI_FUNCTION("addDisallowedUninstallBundlesSync", AddDisallowedUninstallBundlesSync),
        DECLARE_NAPI_FUNCTION("removeDisallowedUninstallBundlesSync", RemoveDisallowedUninstallBundlesSync),
        DECLARE_NAPI_FUNCTION("getDisallowedUninstallBundlesSync", GetDisallowedUninstallBundlesSync),
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

napi_value BundleManagerAddon::Uninstall(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_Uninstall called");
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    auto asyncCallbackInfo = new (std::nothrow) AsyncUninstallCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncUninstallCallbackInfo> callbackPtr{asyncCallbackInfo};
    if (!CheckAndParseUninstallParamType(env, argc, argv, asyncCallbackInfo)) {
        return nullptr;
    }

    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "NativeUninstall", NativeUninstall, NativeUninstallCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void BundleManagerAddon::NativeUninstall(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetBundlesByPolicyType called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncUninstallCallbackInfo *asyncCallbackInfo = static_cast<AsyncUninstallCallbackInfo *>(data);
    auto proxy = BundleManagerProxy::GetBundleManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get BundleManagerProxy");
        return;
    }

    asyncCallbackInfo->ret = proxy->Uninstall(asyncCallbackInfo->elementName, asyncCallbackInfo->bundleName,
        asyncCallbackInfo->userId, asyncCallbackInfo->isKeepData, asyncCallbackInfo->errMessage);
}

napi_value BundleManagerAddon::Install(napi_env env, napi_callback_info info)
{
#ifdef BUNDLE_FRAMEWORK_EDM_ENABLE
    EDMLOGI("NAPI_Install called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    auto asyncCallbackInfo = new (std::nothrow) AsyncInstallCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "Parameter count error");
    if (!CheckAndParseInstallParamType(env, argc, argv, asyncCallbackInfo)) {
        return nullptr;
    }

    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "NativeInstall", NativeInstall, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
#else
    EDMLOGW("BundleManagerAddon::Install Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

void BundleManagerAddon::NativeInstall(napi_env env, void *data)
{
#ifdef BUNDLE_FRAMEWORK_EDM_ENABLE
    EDMLOGI("NAPI_NativeInstall called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncInstallCallbackInfo *asyncCallbackInfo = static_cast<AsyncInstallCallbackInfo *>(data);
    auto proxy = BundleManagerProxy::GetBundleManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get BundleManagerProxy");
        return;
    }

    asyncCallbackInfo->ret = proxy->Install(asyncCallbackInfo->elementName, asyncCallbackInfo->hapFilePaths,
        asyncCallbackInfo->installParam, asyncCallbackInfo->innerCodeMsg);
    EDMLOGI("NAPI_NativeInstall asyncCallbackInfo->ret : %{public}d", asyncCallbackInfo->ret);
#endif
}

void BundleManagerAddon::NativeUninstallCallbackComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCallbackInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfo *>(data);
    napi_value error = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        EDMLOGD("asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &error);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, error);
        } else {
            if (asyncCallbackInfo->ret == EdmReturnErrCode::PARAM_ERROR) {
                napi_reject_deferred(env, asyncCallbackInfo->deferred,
                    CreateError(env, asyncCallbackInfo->ret, asyncCallbackInfo->errMessage));
            } else {
                napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
            }
        }
    } else {
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &error);
        } else {
            if (asyncCallbackInfo->ret == EdmReturnErrCode::PARAM_ERROR) {
                error = CreateError(env, asyncCallbackInfo->ret, asyncCallbackInfo->errMessage);
            } else {
                error = CreateError(env, asyncCallbackInfo->ret);
            }
        }
        napi_value callback = nullptr;
        napi_value result = nullptr;
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_call_function(env, nullptr, callback, ARGS_SIZE_ONE, &error, &result);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

bool BundleManagerAddon::CheckAndParseUninstallParamType(napi_env env, size_t argc, napi_value *argv,
    AsyncUninstallCallbackInfo *asyncCallbackInfo)
{
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->bundleName, argv[ARR_INDEX_ONE]),
        "Parameter bundle name error");
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
    if (argc == ARGS_SIZE_TWO) {
        return true;
    }
    bool hasCallback = argc <= ARGS_SIZE_FIVE ? MatchValueType(env, argv[argc - 1], napi_function) :
                                                MatchValueType(env, argv[ARR_INDEX_FOUR], napi_function);
    if (hasCallback) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseCallback(env, asyncCallbackInfo->callback,
            argc <= ARGS_SIZE_FIVE ? argv[argc - 1] : argv[ARR_INDEX_FOUR]), "Parameter callback error");
        switch (argc) {
            case ARGS_SIZE_THREE:
                break;
            case ARGS_SIZE_FOUR:
                if (MatchValueType(env, argv[ARR_INDEX_TWO], napi_number)) {
                    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->userId, argv[ARR_INDEX_TWO]),
                        "Parameter userId error");
                } else if (MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean)) {
                    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, asyncCallbackInfo->isKeepData,
                        argv[ARR_INDEX_TWO]), "Parameter isKeepData error");
                } else {
                    ASSERT_AND_THROW_PARAM_ERROR(env, false, "Parameter three type error");
                }
                break;
            default:
                ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->userId, argv[ARR_INDEX_TWO]),
                    "Parameter userId error");
                ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, asyncCallbackInfo->isKeepData, argv[ARR_INDEX_THREE]),
                    "Parameter isKeepData error");
        }
        return true;
    }
    if (argc == ARGS_SIZE_THREE) {
        if (!ParseInt(env, asyncCallbackInfo->userId, argv[ARR_INDEX_TWO])) {
            AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
            ParseBool(env, asyncCallbackInfo->isKeepData, argv[ARR_INDEX_TWO]);
        }
        return true;
    }
    if (!ParseInt(env, asyncCallbackInfo->userId, argv[ARR_INDEX_TWO])) {
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
    }
    ParseBool(env, asyncCallbackInfo->isKeepData, argv[ARR_INDEX_THREE]);
    return true;
}

#ifdef BUNDLE_FRAMEWORK_EDM_ENABLE
bool BundleManagerAddon::jsObjectToInstallParam(napi_env env, napi_value object,
    OHOS::AppExecFwk::InstallParam &installParam)
{
    int32_t installFlag = 0;
    if (!JsObjectToInt(env, object, "userId", false, installParam.userId) ||
        !JsObjectToInt(env, object, "installFlag", false, installFlag)) {
        return false;
    }
    bool hasProperty = false;
    if (napi_has_named_property(env, object, "userId", &hasProperty) == napi_ok && !hasProperty) {
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(installParam.userId);
    }
    if ((installFlag != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::NORMAL)) &&
        (installFlag != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::REPLACE_EXISTING)) &&
        (installFlag != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::FREE_INSTALL))) {
        EDMLOGE("invalid installFlag param");
        return false;
    }
    installParam.installFlag = static_cast<OHOS::AppExecFwk::InstallFlag>(installFlag);
    return true;
}

bool BundleManagerAddon::CheckAndParseInstallParamType(napi_env env, size_t argc, napi_value *argv,
    AsyncInstallCallbackInfo *asyncCallbackInfo)
{
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, asyncCallbackInfo->hapFilePaths, argv[ARR_INDEX_ONE]),
        "Parameter bundleFilePaths error");
    if (argc == ARGS_SIZE_TWO) {
        return true;
    }
    bool hasCallback = argc <= ARGS_SIZE_FOUR ? MatchValueType(env, argv[argc - 1], napi_function) :
                                                MatchValueType(env, argv[ARR_INDEX_THREE], napi_function);
    if (hasCallback) {
        ASSERT_AND_THROW_PARAM_ERROR(env,
            ParseCallback(env, asyncCallbackInfo->callback,
                argc <= ARGS_SIZE_FOUR ? argv[argc - 1] : argv[ARGS_SIZE_THREE]),
            "Parameter callback error");
        EDMLOGI("CheckAndParseInstallParamType ParseCallback success");
        if (argc == ARGS_SIZE_FOUR) {
            ASSERT_AND_THROW_PARAM_ERROR(env,
                jsObjectToInstallParam(env, argv[ARR_INDEX_TWO], asyncCallbackInfo->installParam),
                "installParam param error");
        }
        return true;
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, jsObjectToInstallParam(env, argv[ARR_INDEX_TWO], asyncCallbackInfo->installParam),
        "installParam param error");
    return true;
}
#endif

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
    std::unique_ptr<AsyncBundlesCallbackInfo> callbackPtr{asyncCallbackInfo};
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
        ASSERT_AND_THROW_PARAM_ERROR(env,
            ParseCallback(env, asyncCallbackInfo->callback,
                argc <= ARR_INDEX_THREE ? argv[argc - 1] : argv[ARR_INDEX_TWO]),
            "Parameter callback error");
    }
    InitCallbackInfoPolicyType(workName, asyncCallbackInfo);
    EDMLOGI("GetInstallBundles::%{public}s policyType = %{public}d", workName.c_str(), asyncCallbackInfo->policyType);
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, workName, execute, NativeArrayStringCallbackComplete);
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

    asyncCallbackInfo->ret = proxy->GetBundlesByPolicyType(asyncCallbackInfo->elementName, asyncCallbackInfo->userId,
        asyncCallbackInfo->arrayStringRet, asyncCallbackInfo->policyType);
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

bool BundleManagerAddon::CheckAddInstallBundlesParamType(napi_env env, size_t argc, napi_value *argv, bool &hasCallback,
    bool &hasUserId)
{
    if (!MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) ||
        !MatchValueType(env, argv[ARR_INDEX_ONE], napi_object)) {
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
    std::unique_ptr<AsyncBundlesCallbackInfo> callbackPtr{asyncCallbackInfo};
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
        "asyncCallbackInfo->abilityname:%{public}s", asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (hasUserId) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->userId, argv[ARR_INDEX_TWO]),
            "Parameter user id error");
    } else {
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
    }
    if (hasCallback) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseCallback(env, asyncCallbackInfo->callback,
            argc <= ARGS_SIZE_FOUR ? argv[argc - 1] : argv[ARR_INDEX_THREE]), "Parameter callback error");
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

napi_value BundleManagerAddon::AddAllowedInstallBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddAllowedInstallBundlesSync called");
    return AddOrRemoveInstallBundlesSync(env, info, "AddAllowedInstallBundles", true);
}

napi_value BundleManagerAddon::AddDisallowedInstallBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddDisallowedInstallBundlesSync called");
    return AddOrRemoveInstallBundlesSync(env, info, "AddDisallowedInstallBundles", true);
}

napi_value BundleManagerAddon::AddDisallowedUninstallBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddDisallowedUninstallBundlesSync called");
    return AddOrRemoveInstallBundlesSync(env, info, "AddDisallowedUninstallBundles", true);
}

napi_value BundleManagerAddon::RemoveAllowedInstallBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveAllowedInstallBundlesSync called");
    return AddOrRemoveInstallBundlesSync(env, info, "RemoveAllowedInstallBundles", false);
}

napi_value BundleManagerAddon::RemoveDisallowedInstallBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveDisallowedInstallBundlesSync called");
    return AddOrRemoveInstallBundlesSync(env, info, "RemoveDisallowedInstallBundles", false);
}

napi_value BundleManagerAddon::RemoveDisallowedUninstallBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveDisallowedUninstallBundlesSync called");
    return AddOrRemoveInstallBundlesSync(env, info, "RemoveDisallowedUninstallBundles", false);
}

napi_value BundleManagerAddon::AddOrRemoveInstallBundlesSync(napi_env env, napi_callback_info info,
    const std::string &workName, bool isAdd)
{
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
    ASSERT_AND_THROW_PARAM_ERROR(env, appIds.size() <= EdmConstants::APPID_MAX_SIZE,
        "parameter appIds too large");
    EDMLOGD("CheckAddOrRemoveInstallBundlesParam: "
        "elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    int32_t accountId = 0;
    if (hasAccountId) {
        ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_number),
            "parameter accountId error");
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_TWO]),
            "parameter accountId parse error");
    } else {
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(accountId);
    }
    int32_t policyType = 0;
    InitPolicyType(workName, policyType);
    EDMLOGI("AddOrRemoveInstallBundlesSync::%{public}s policyType = %{public}d", workName.c_str(), policyType);

    auto bundleManagerProxy = BundleManagerProxy::GetBundleManagerProxy();
    if (bundleManagerProxy == nullptr) {
        EDMLOGE("can not get BundleManagerProxy");
        return nullptr;
    }
    int32_t ret = ERR_OK;
    if (isAdd) {
        ret = bundleManagerProxy->AddBundlesByPolicyType(elementName, appIds, accountId, policyType);
    } else {
        ret = bundleManagerProxy->RemoveBundlesByPolicyType(elementName, appIds, accountId, policyType);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

void BundleManagerAddon::InitPolicyType(const std::string &workName, int32_t &policyType)
{
    auto iter = POLICY_TYPE_MAP.find(workName);
    if (iter != POLICY_TYPE_MAP.end()) {
        policyType = iter->second;
    } else {
        EDMLOGI("policy type map get error");
        policyType = static_cast<int32_t>(PolicyType::INVALID_TYPE);
    }
}

napi_value BundleManagerAddon::GetAllowedInstallBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAllowedInstallBundles called");
    return GetAllowedOrDisallowedInstallBundlesSync(env, info, "GetAllowedInstallBundles");
}

napi_value BundleManagerAddon::GetDisallowedInstallBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedInstallBundles called");
    return GetAllowedOrDisallowedInstallBundlesSync(env, info, "GetDisallowedInstallBundles");
}

napi_value BundleManagerAddon::GetDisallowedUninstallBundlesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedUninstallBundles called");
    return GetAllowedOrDisallowedInstallBundlesSync(env, info, "GetDisallowedUninstallBundles");
}

napi_value BundleManagerAddon::GetAllowedOrDisallowedInstallBundlesSync(napi_env env, napi_callback_info info,
    const std::string &workName)
{
    EDMLOGI("NAPI_GetAllowedOrDisallowedInstallBundlesSync called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    bool hasAccountId = (argc == ARGS_SIZE_TWO);
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    EDMLOGD("GetAllowedOrDisallowedInstallBundlesSync: "
        "elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    int32_t accountId = 0;
    if (hasAccountId) {
        ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_number),
            "parameter accountId error");
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_ONE]),
            "parameter accountId parse error");
    } else {
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(accountId);
    }
    int32_t policyType = 0;
    InitPolicyType(workName, policyType);
    EDMLOGI("GetAllowedOrDisallowedInstallBundlesSync::%{public}s "
        "policyType = %{public}d", workName.c_str(), policyType);

    auto bundleManagerProxy = BundleManagerProxy::GetBundleManagerProxy();
    if (bundleManagerProxy == nullptr) {
        EDMLOGE("can not get BundleManagerProxy");
        return nullptr;
    }
    std::vector<std::string> appIds;
    int32_t ret = bundleManagerProxy->GetBundlesByPolicyType(elementName, accountId, appIds, policyType);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    napi_value result = nullptr;
    napi_create_array(env, &result);
    ConvertStringVectorToJS(env, appIds, result);
    return result;
}

static napi_module g_bundleManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BundleManagerAddon::Init,
    .nm_modname = "enterprise.bundleManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void BundleManagerRegister()
{
    napi_module_register(&g_bundleManagerModule);
}