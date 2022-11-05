/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "admin_manager_addon.h"

#include "edm_log.h"
#include "hisysevent_adapter.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

using namespace OHOS::EDM;

std::shared_ptr<EnterpriseDeviceMgrProxy> AdminManager::proxy_ = nullptr;

napi_value AdminManager::EnableAdmin(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_EnableAdmin called");
    ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "enableAdmin", "");
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    bool hasCallback = false;
    bool hasUserId = false;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    auto asyncCallbackInfo = new (std::nothrow) AsyncEnableAdminCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncEnableAdminCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, checkEnableAdminParamType(env, argc, argv, hasCallback, hasUserId),
        "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseEnterpriseInfo(env, asyncCallbackInfo->entInfo, argv[ARR_INDEX_ONE]),
        "Parameter enterprise info error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->adminType, argv[ARR_INDEX_TWO]),
        "Parameter admin type error");

    EDMLOGD("EnableAdmin::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s , adminType:%{public}d",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str(),
        asyncCallbackInfo->adminType);
    if (hasUserId) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->userId, argv[ARR_INDEX_THREE]),
            "Parameter user id error");
    } else {
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
    }
    if (hasCallback) {
        napi_create_reference(env, argv[argc - 1], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "EnableAdmin",
        NativeEnableAdmin, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void AdminManager::NativeEnableAdmin(napi_env env, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncEnableAdminCallbackInfo *asyncCallbackInfo = static_cast<AsyncEnableAdminCallbackInfo *>(data);
    auto proxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy_ == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }

    asyncCallbackInfo->ret = proxy_->EnableAdmin(asyncCallbackInfo->elementName, asyncCallbackInfo->entInfo,
        static_cast<AdminType>(asyncCallbackInfo->adminType), asyncCallbackInfo->userId);
}

bool AdminManager::checkEnableAdminParamType(napi_env env, size_t argc,
    napi_value* argv, bool &hasCallback, bool &hasUserId)
{
    EDMLOGI("argc = %{public}zu", argc);
    if (argc == ARGS_SIZE_THREE) {
        hasCallback = false;
        hasUserId = false;
        EDMLOGI("hasCallback = false; hasUserId = false;");
        return MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
            MatchValueType(env, argv[ARR_INDEX_ONE], napi_object) &&
            MatchValueType(env, argv[ARR_INDEX_TWO], napi_number);
    }

    if (argc == ARGS_SIZE_FOUR) {
        if (MatchValueType(env, argv[ARR_INDEX_THREE], napi_function)) {
            hasCallback = true;
            hasUserId = false;
            EDMLOGI("hasCallback = true; hasUserId = false;");
            return MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
                MatchValueType(env, argv[ARR_INDEX_ONE], napi_object) &&
                MatchValueType(env, argv[ARR_INDEX_TWO], napi_number);
        } else {
            hasCallback = false;
            hasUserId = true;
            EDMLOGI("hasCallback = false;  hasUserId = true;");
            return MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
                MatchValueType(env, argv[ARR_INDEX_ONE], napi_object) &&
                MatchValueType(env, argv[ARR_INDEX_TWO], napi_number) &&
                MatchValueType(env, argv[ARR_INDEX_THREE], napi_number);
        }
    }
    hasCallback = true;
    hasUserId = true;
    EDMLOGI("hasCallback = true; hasUserId = true;");
    return MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_TWO], napi_number) &&
        MatchValueType(env, argv[ARR_INDEX_THREE], napi_number) &&
        MatchValueType(env, argv[ARR_INDEX_FOUR], napi_function);
}

bool AdminManager::checkAdminWithUserIdParamType(napi_env env, size_t argc,
    napi_value* argv, bool &hasCallback, bool &hasUserId)
{
    EDMLOGI("argc = %{public}zu", argc);
    if (argc == ARGS_SIZE_ONE) {
        hasCallback = false;
        hasUserId = false;
        EDMLOGI("hasCallback = false; hasUserId = false;");
        return MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    }

    if (argc == ARGS_SIZE_TWO) {
        if (MatchValueType(env, argv[ARR_INDEX_ONE], napi_function)) {
            hasCallback = true;
            hasUserId = false;
            EDMLOGI("hasCallback = true; hasUserId = false;");
            return MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
        } else {
            hasCallback = false;
            hasUserId = true;
            EDMLOGI("hasCallback = false;  hasUserId = true;");
            return MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
                MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
        }
    }
    hasCallback = true;
    hasUserId = true;
    EDMLOGI("hasCallback = true; hasUserId = true;");
    return MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_number) &&
        MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
}

napi_value AdminManager::DisableAdmin(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_DisableAdmin called");
    ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "disableAdmin", "");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    bool hasCallback = false;
    bool hasUserId = false;
    auto asyncCallbackInfo = new (std::nothrow) AsyncDisableAdminCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncDisableAdminCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, checkAdminWithUserIdParamType(env, argc, argv, hasCallback, hasUserId),
        "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");

    EDMLOGD("DisableAdmin::asyncCallbackInfo->elementName.bundlename %{public}s, "
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
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "DisableAdmin", NativeDisableAdmin,
        NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void AdminManager::NativeDisableAdmin(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeDisableAdmin called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncDisableAdminCallbackInfo *asyncCallbackInfo = static_cast<AsyncDisableAdminCallbackInfo *>(data);
    auto proxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy_ == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }

    asyncCallbackInfo->ret = proxy_->DisableAdmin(asyncCallbackInfo->elementName, asyncCallbackInfo->userId);
}

napi_value AdminManager::DisableSuperAdmin(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_DisableSuperAdmin called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");

    auto asyncCallbackInfo = new (std::nothrow) AsyncDisableSuperAdminCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncDisableSuperAdminCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->bundleName, argv[ARR_INDEX_ZERO]),
        "parameter bundle name error");
    if (argc > ARGS_SIZE_ONE) {
        bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ONE], napi_function);
        napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
        ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    }

    EDMLOGD("DisableSuperAdmin: asyncCallbackInfo->elementName.bundlename %{public}s",
        asyncCallbackInfo->bundleName.c_str());
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "DisableSuperAdmin", NativeDisableSuperAdmin,
        NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void AdminManager::NativeDisableSuperAdmin(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeDisableSuperAdmin called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncDisableSuperAdminCallbackInfo *asyncCallbackInfo =
        static_cast<AsyncDisableSuperAdminCallbackInfo *>(data);
    auto proxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy_ == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbackInfo->ret = proxy_->DisableSuperAdmin(asyncCallbackInfo->bundleName);
}

napi_value AdminManager::GetEnterpriseInfo(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetEnterpriseInfo called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    if (argc > ARGS_SIZE_ONE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncGetEnterpriseInfoCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncGetEnterpriseInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD("EnableAdmin: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("GetEnterpriseInfo by callback");
        napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "GetEnterpriseInfo", NativeGetEnterpriseInfo,
        NativeGetEnterpriseInfoComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void AdminManager::NativeGetEnterpriseInfo(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeDisableSuperAdmin called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncGetEnterpriseInfoCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetEnterpriseInfoCallbackInfo *>(data);
    auto proxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy_ == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbackInfo->ret = proxy_->GetEnterpriseInfo(asyncCallbackInfo->elementName, asyncCallbackInfo->entInfo);
}

void AdminManager::NativeGetEnterpriseInfoComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncGetEnterpriseInfoCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetEnterpriseInfoCallbackInfo *>(data);

    napi_value result[2] = { 0 };
    if (asyncCallbackInfo->ret == ERR_OK) {
        napi_get_null(env, &result[ARR_INDEX_ZERO]);
        napi_create_object(env, &result[ARR_INDEX_ONE]);
        ConvertEnterpriseInfo(env, result[ARR_INDEX_ONE], asyncCallbackInfo->entInfo);
        EDMLOGD("NativeGetEnterpriseInfoComplete::asyncCallbackInfo->entInfo->enterpriseName %{public}s, "
            "asyncCallbackInfo->entInfo->description:%{public}s",
            asyncCallbackInfo->entInfo.enterpriseName.c_str(), asyncCallbackInfo->entInfo.description.c_str());
    } else {
        result[ARR_INDEX_ZERO] = CreateError(env, asyncCallbackInfo->ret);
        napi_get_null(env, &result[ARR_INDEX_ONE]);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARR_INDEX_ONE]);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, result[ARR_INDEX_ZERO]);
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_call_function(env, nullptr, callback, sizeof(result) / sizeof(result[ARR_INDEX_ZERO]),
            result, &placeHolder);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
}

napi_value AdminManager::SetEnterpriseInfo(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetEnterpriseInfo called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag =
        MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) && MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncSetEnterpriseInfoCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSetEnterpriseInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    ret = ParseEnterpriseInfo(env, asyncCallbackInfo->entInfo, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "enterprise info param error");
    EDMLOGD("SetEnterpriseInfo: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_TWO) {
        napi_create_reference(env, argv[ARR_INDEX_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "SetEnterpriseInfo", NativeSetEnterpriseInfo,
        NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void AdminManager::NativeSetEnterpriseInfo(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetEnterpriseInfo called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncSetEnterpriseInfoCallbackInfo *asyncCallbackInfo = static_cast<AsyncSetEnterpriseInfoCallbackInfo *>(data);
    auto proxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy_ == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbackInfo->ret = proxy_->SetEnterpriseInfo(asyncCallbackInfo->elementName, asyncCallbackInfo->entInfo);
}

napi_value AdminManager::IsSuperAdmin(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsSuperAdmin called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncIsSuperAdminCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncIsSuperAdminCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->bundleName, argv[ARR_INDEX_ZERO]),
        "parameter bundle name error");
    EDMLOGD("IsSuperAdmin: asyncCallbackInfo->elementName.bundlename %{public}s",
        asyncCallbackInfo->bundleName.c_str());
    if (argc > ARGS_SIZE_ONE) {
        bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ONE], napi_function);
        ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
        napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "IsSuperAdmin",
        NativeIsSuperAdmin, NativeBoolCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

napi_value AdminManager::isAdminEnabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("isAdminEnabled called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    bool hasCallback = false;
    bool hasUserId = false;
    auto asyncCallbackInfo = new (std::nothrow) AsyncIsAdminEnabledCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncIsAdminEnabledCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, checkAdminWithUserIdParamType(env, argc, argv, hasCallback, hasUserId),
        "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    EDMLOGD("isAdminEnabled::asyncCallbackInfo->elementName.bundlename %{public}s, "
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

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "isAdminEnabled",
        NativeIsAdminEnabled, NativeBoolCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void AdminManager::NativeIsSuperAdmin(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeIsSuperAdmin called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncIsSuperAdminCallbackInfo *asyncCallbackInfo = static_cast<AsyncIsSuperAdminCallbackInfo *>(data);
    auto proxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy_ == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbackInfo->ret = ERR_OK;
    asyncCallbackInfo->boolRet = proxy_->IsSuperAdmin(asyncCallbackInfo->bundleName);
}

void AdminManager::NativeIsAdminEnabled(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeIsAdminEnabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncIsAdminEnabledCallbackInfo *asyncCallbackInfo = static_cast<AsyncIsAdminEnabledCallbackInfo *>(data);
    auto proxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy_ == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbackInfo->ret = ERR_OK;
    asyncCallbackInfo->boolRet = proxy_->IsAdminEnabled(asyncCallbackInfo->elementName, asyncCallbackInfo->userId);
}

napi_value AdminManager::SubscribeManagedEvent(napi_env env, napi_callback_info info)
{
    EDMLOGI("SubscribeManagedEvent called");
    return HandleManagedEvent(env, info, true);
}

napi_value AdminManager::UnsubscribeManagedEvent(napi_env env, napi_callback_info info)
{
    EDMLOGI("UnsubscribeManagedEvent called");
    return HandleManagedEvent(env, info, false);
}

napi_value AdminManager::HandleManagedEvent(napi_env env, napi_callback_info info, bool subscribe)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "Parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
		MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncSubscribeManagedEventCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSubscribeManagedEventCallbackInfo> callbackPtr {asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    ret = ParseManagedEvent(env, asyncCallbackInfo->managedEvent, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "managed event param error");
    if (argc > ARGS_SIZE_TWO) {
        napi_create_reference(env, argv[ARR_INDEX_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    asyncCallbackInfo->subscribe = subscribe;
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "SubscribeManagedEvent",
        NativeSubscribeManagedEvent, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void AdminManager::NativeSubscribeManagedEvent(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSubscribeManagedEvent called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncSubscribeManagedEventCallbackInfo *asyncCallbakInfo =
        static_cast<AsyncSubscribeManagedEventCallbackInfo *>(data);
    auto proxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy_ == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbakInfo->ret = proxy_->HandleManagedEvent(asyncCallbakInfo->elementName,
        asyncCallbakInfo->managedEvent, asyncCallbakInfo->subscribe);
}

bool AdminManager::ParseEnterpriseInfo(napi_env env, EntInfo &enterpriseInfo, napi_value args)
{
    napi_valuetype valueType;
    if (napi_typeof(env, args, &valueType) != napi_ok || valueType != napi_object) {
        EDMLOGE("Parameter enterprise info error");
        return false;
    }
    std::string name;
    std::string description;
    napi_value prop = nullptr;
    EDMLOGD("ParseEnterpriseInfo name");
    if (napi_get_named_property(env, args, "name", &prop) != napi_ok || !GetStringFromNAPI(env, prop, name)) {
        EDMLOGE("ParseEnterpriseInfo name param error");
        return false;
    }
    EDMLOGD("ParseEnterpriseInfo name %{public}s ", name.c_str());

    EDMLOGD("ParseEnterpriseInfo description");
    prop = nullptr;
    if (napi_get_named_property(env, args, "description", &prop) != napi_ok ||
        !GetStringFromNAPI(env, prop, description)) {
        EDMLOGE("ParseEnterpriseInfo description param error");
        return false;
    }
    EDMLOGD("ParseEnterpriseInfo description %{public}s", description.c_str());

    enterpriseInfo.enterpriseName = name;
    enterpriseInfo.description = description;
    return true;
}

void AdminManager::ConvertEnterpriseInfo(napi_env env, napi_value objEntInfo, EntInfo &entInfo)
{
    std::string enterpriseName = entInfo.enterpriseName;
    std::string description = entInfo.description;
    napi_value nEnterpriseName;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_string_utf8(env, enterpriseName.c_str(), NAPI_AUTO_LENGTH, &nEnterpriseName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objEntInfo, "name", nEnterpriseName));

    napi_value nDescription;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, description.c_str(), NAPI_AUTO_LENGTH, &nDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objEntInfo, "description", nDescription));
}

bool AdminManager::ParseManagedEvent(napi_env env,
    std::vector<uint32_t> &managedEvent, napi_value args)
{
    uint32_t len;
    if (napi_get_array_length(env, args, &len) != napi_ok) {
        return false;
    }
    for (uint32_t i = 0; i < len; i++) {
        napi_value event;
        if (napi_get_element(env, args, i, &event) != napi_ok) {
            return false;
        }
        uint32_t value = 0;
        if (napi_get_value_uint32(env, event, &value) != napi_ok) {
            return false;
        }
        managedEvent.push_back(value);
    }
    return true;
}

void AdminManager::CreateAdminTypeObject(napi_env env, napi_value value)
{
    napi_value nNomal;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, AdminType::NORMAL, &nNomal));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ADMIN_TYPE_NORMAL", nNomal));
    napi_value nSuper;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, AdminType::ENT, &nSuper));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ADMIN_TYPE_SUPER", nSuper));
}

void AdminManager::CreateManagedEventObject(napi_env env, napi_value value)
{
    napi_value nBundleAdded;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED), &nBundleAdded));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_BUNDLE_ADDED", nBundleAdded));
    napi_value nBundleRemoved;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(ManagedEvent::BUNDLE_REMOVED), &nBundleRemoved));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_BUNDLE_REMOVED", nBundleRemoved));
}

napi_value AdminManager::Init(napi_env env, napi_value exports)
{
    napi_value nAdminType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nAdminType));
    CreateAdminTypeObject(env, nAdminType);

    napi_value nManagedEvent = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nManagedEvent));
    CreateManagedEventObject(env, nManagedEvent);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("enableAdmin", EnableAdmin),
        DECLARE_NAPI_FUNCTION("disableAdmin", DisableAdmin),
        DECLARE_NAPI_FUNCTION("disableSuperAdmin", DisableSuperAdmin),
        DECLARE_NAPI_FUNCTION("isAdminEnabled", isAdminEnabled),
        DECLARE_NAPI_FUNCTION("getEnterpriseInfo", GetEnterpriseInfo),
        DECLARE_NAPI_FUNCTION("setEnterpriseInfo", SetEnterpriseInfo),
        DECLARE_NAPI_FUNCTION("isSuperAdmin", IsSuperAdmin),
        DECLARE_NAPI_FUNCTION("subscribeManagedEvent", SubscribeManagedEvent),
        DECLARE_NAPI_FUNCTION("unsubscribeManagedEvent", UnsubscribeManagedEvent),

        DECLARE_NAPI_PROPERTY("AdminType", nAdminType),
        DECLARE_NAPI_PROPERTY("ManagedEvent", nManagedEvent),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

static napi_module g_edmServiceModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = AdminManager::Init,
    .nm_modname = "enterprise.adminManager",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void EdmServiceRegister()
{
    napi_module_register(&g_edmServiceModule);
}
