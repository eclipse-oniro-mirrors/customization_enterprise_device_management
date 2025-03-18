/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "ability_context.h"
#include "ability_manager_client.h"
#include "admin_manager_addon.h"

#include "edm_log.h"
#include "hisysevent_adapter.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "napi_base_context.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_manager.h"
#endif
#include "system_ability_definition.h"

using namespace OHOS::EDM;
namespace {
const std::string ADMIN_PROVISIONING_ABILITY_NAME = "ByodAdminProvisionAbility";
const int32_t JS_BYOD_TYPE = 2;
const uint32_t MAX_ADMINPROVISION_PARAM_NUM = 10;
const uint32_t MIN_ACTIVATEID_LEN = 32;
const uint32_t MAX_ACTIVATEID_LEN = 256;
const uint32_t MAX_CUSTOMIZEDINFO_LEN = 10240;
const std::string ACTIVATEID = "activateId";
const std::string CUSTOMIZEDINFO = "customizedInfo";
}
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
    std::unique_ptr<AsyncEnableAdminCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckEnableAdminParamType(env, argc, argv, hasCallback, hasUserId),
        "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseEnterpriseInfo(env, asyncCallbackInfo->entInfo, argv[ARR_INDEX_ONE]),
        "Parameter enterprise info error");
    int32_t jsAdminType;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, jsAdminType, argv[ARR_INDEX_TWO]), "Parameter admin type error");
    asyncCallbackInfo->adminType = JsAdminTypeToAdminType(jsAdminType);
    EDMLOGD("EnableAdmin::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s , adminType:%{public}d",
        asyncCallbackInfo->elementName.GetBundleName().c_str(), asyncCallbackInfo->elementName.GetAbilityName().c_str(),
        asyncCallbackInfo->adminType);
    if (hasUserId) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->userId, argv[ARR_INDEX_THREE]),
            "Parameter user id error");
    } else {
#ifdef OS_ACCOUNT_EDM_ENABLE
        AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(asyncCallbackInfo->userId);
#endif
    }
    if (hasCallback) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseCallback(env, asyncCallbackInfo->callback,
            argc <= ARGS_SIZE_FIVE ? argv[argc - 1] : argv[ARR_INDEX_FOUR]), "Parameter callback error");
    }
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "EnableAdmin", NativeEnableAdmin, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

int32_t AdminManager::JsAdminTypeToAdminType(int32_t jsAdminType)
{
    if (jsAdminType == JS_BYOD_TYPE) {
        return static_cast<int32_t>(AdminType::BYOD);
    }
    if (jsAdminType == static_cast<int32_t>(AdminType::NORMAL) || jsAdminType == static_cast<int32_t>(AdminType::ENT)) {
        return jsAdminType;
    }
    return static_cast<int32_t>(AdminType::UNKNOWN);
}

int32_t AdminManager::AdminTypeToJsAdminType(int32_t AdminType)
{
    if (AdminType == static_cast<int32_t>(AdminType::BYOD)) {
        return JS_BYOD_TYPE;
    }
    if (AdminType == static_cast<int32_t>(AdminType::NORMAL) || AdminType == static_cast<int32_t>(AdminType::ENT)) {
        return AdminType;
    }
    return static_cast<int32_t>(AdminType::UNKNOWN);
}

napi_value AdminManager::ReplaceSuperAdmin(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_ReplaceSuperAdmin called");
    ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "ReplaceSuperAdmin", "");
    AppExecFwk::ElementName oldAdmin;
    AppExecFwk::ElementName newAdmin;
    bool keepPolicy = true;
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "Parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean);

    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, oldAdmin, argv[ARR_INDEX_ZERO]),
        "oldAdmin param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, newAdmin, argv[ARR_INDEX_ONE]),
        "newAdmin param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, keepPolicy, argv[ARR_INDEX_TWO]),
        "keepPolicy param error");

    EDMLOGD(
        "ReplaceSuperAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        newAdmin.GetBundleName().c_str(),
        newAdmin.GetAbilityName().c_str());
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    int32_t retCode = proxy->ReplaceSuperAdmin(oldAdmin, newAdmin, keepPolicy);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

AdminType AdminManager::ParseAdminType(int32_t type)
{
    if (type == static_cast<int32_t>(AdminType::NORMAL) || type == static_cast<int32_t>(AdminType::ENT) ||
        type == static_cast<int32_t>(AdminType::BYOD)) {
        return static_cast<AdminType>(type);
    }
    return AdminType::UNKNOWN;
}

void AdminManager::NativeEnableAdmin(napi_env env, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncEnableAdminCallbackInfo *asyncCallbackInfo = static_cast<AsyncEnableAdminCallbackInfo *>(data);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();

    asyncCallbackInfo->ret = proxy->EnableAdmin(asyncCallbackInfo->elementName, asyncCallbackInfo->entInfo,
        ParseAdminType(asyncCallbackInfo->adminType), asyncCallbackInfo->userId);
}

bool AdminManager::CheckEnableAdminParamType(napi_env env, size_t argc, napi_value *argv, bool &hasCallback,
    bool &hasUserId)
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
    std::unique_ptr<AsyncDisableAdminCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckAdminWithUserIdParamType(env, argc, argv, hasCallback, hasUserId),
        "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");

    EDMLOGD(
        "DisableAdmin::asyncCallbackInfo->elementName.bundlename %{public}s, "
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
                argc <= ARGS_SIZE_THREE ? argv[argc - 1] : argv[ARR_INDEX_TWO]),
            "Parameter callback error");
    }
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "DisableAdmin", NativeDisableAdmin, NativeVoidCallbackComplete);
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
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();

    asyncCallbackInfo->ret = proxy->DisableAdmin(asyncCallbackInfo->elementName, asyncCallbackInfo->userId);
}

napi_value AdminManager::DisableSuperAdmin(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_DisableSuperAdmin called");
    auto convertBundleName2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
        std::string bundleName;
        bool isStr = ParseString(env, bundleName, argv);
        if (!isStr) {
            return false;
        }
        data.WriteString(bundleName);
        return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "DisableSuperAdmin";
    addonMethodSign.argsType = {EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {convertBundleName2Data};
    addonMethodSign.methodAttribute = MethodAttribute::OPERATE_ADMIN;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeDisableSuperAdmin, NativeVoidCallbackComplete);
}

void AdminManager::NativeDisableSuperAdmin(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeDisableSuperAdmin called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    asyncCallbackInfo->ret = proxy->DisableSuperAdmin(asyncCallbackInfo->data);
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
    std::unique_ptr<AsyncGetEnterpriseInfoCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD(
        "EnableAdmin: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("GetEnterpriseInfo by callback");
        NAPI_CALL(env, napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
    }

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "GetEnterpriseInfo", NativeGetEnterpriseInfo,
        NativeGetEnterpriseInfoComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void AdminManager::NativeGetEnterpriseInfo(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetEnterpriseInfo called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncGetEnterpriseInfoCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetEnterpriseInfoCallbackInfo *>(data);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    asyncCallbackInfo->ret = proxy->GetEnterpriseInfo(asyncCallbackInfo->elementName, asyncCallbackInfo->entInfo);
}

void AdminManager::NativeGetEnterpriseInfoComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncGetEnterpriseInfoCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetEnterpriseInfoCallbackInfo *>(data);

    napi_value result[2] = {0};
    if (asyncCallbackInfo->ret == ERR_OK) {
        napi_get_null(env, &result[ARR_INDEX_ZERO]);
        napi_create_object(env, &result[ARR_INDEX_ONE]);
        ConvertEnterpriseInfo(env, result[ARR_INDEX_ONE], asyncCallbackInfo->entInfo);
        EDMLOGD(
            "NativeGetEnterpriseInfoComplete::asyncCallbackInfo->entInfo->enterpriseName %{public}s, "
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
        napi_call_function(env, nullptr, callback, sizeof(result) / sizeof(result[ARR_INDEX_ZERO]), result,
            &placeHolder);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
}

napi_value AdminManager::SetEnterpriseInfo(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetEnterpriseInfo called");
    auto convertEntInfo2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
        EntInfo entInfo;
        bool isEntInfo = ParseEnterpriseInfo(env, entInfo, argv);
        if (!isEntInfo) {
            return false;
        }
        entInfo.Marshalling(data);
        return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetEnterpriseInfo";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {nullptr, convertEntInfo2Data};
    addonMethodSign.methodAttribute = MethodAttribute::OPERATE_ADMIN;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeSetEnterpriseInfo, NativeVoidCallbackComplete);
}

void AdminManager::NativeSetEnterpriseInfo(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetEnterpriseInfo called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    asyncCallbackInfo->ret = proxy->SetEnterpriseInfo(asyncCallbackInfo->data);
}

napi_value AdminManager::SetAdminRunningMode(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetAdminRunningMode called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetAdminRunningMode";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::UINT32};
    addonMethodSign.methodAttribute = MethodAttribute::OPERATE_ADMIN;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = EnterpriseDeviceMgrProxy::GetInstance()->SetAdminRunningMode(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value AdminManager::IsSuperAdmin(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsSuperAdmin called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "IsSuperAdmin";
    addonMethodSign.argsType = {EdmAddonCommonType::STRING};
    addonMethodSign.methodAttribute = MethodAttribute::OPERATE_ADMIN;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeIsSuperAdmin, NativeBoolCallbackComplete);
}

napi_value AdminManager::IsAdminEnabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("IsAdminEnabled called");
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
    std::unique_ptr<AsyncIsAdminEnabledCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckAdminWithUserIdParamType(env, argc, argv, hasCallback, hasUserId),
        "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    EDMLOGD(
        "IsAdminEnabled::asyncCallbackInfo->elementName.bundlename %{public}s, "
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
                argc <= ARGS_SIZE_THREE ? argv[argc - 1] : argv[ARR_INDEX_TWO]),
            "Parameter callback error");
    }

    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "isAdminEnabled", NativeIsAdminEnabled, NativeBoolCallbackComplete);
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
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    asyncCallbackInfo->ret = proxy->IsSuperAdmin(asyncCallbackInfo->data, asyncCallbackInfo->boolRet);
}

void AdminManager::NativeIsAdminEnabled(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeIsAdminEnabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncIsAdminEnabledCallbackInfo *asyncCallbackInfo = static_cast<AsyncIsAdminEnabledCallbackInfo *>(data);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    asyncCallbackInfo->ret =
        proxy->IsAdminEnabled(asyncCallbackInfo->elementName, asyncCallbackInfo->userId, asyncCallbackInfo->boolRet);
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
    bool matchFlag =
        MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) && MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncSubscribeManagedEventCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSubscribeManagedEventCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    ret = ParseManagedEvent(env, asyncCallbackInfo->managedEvent, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "managed event param error");
    if (argc > ARGS_SIZE_TWO) {
        NAPI_CALL(env, napi_create_reference(env, argv[ARR_INDEX_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
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
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    asyncCallbakInfo->ret = proxy->HandleManagedEvent(asyncCallbakInfo->elementName, asyncCallbakInfo->managedEvent,
        asyncCallbakInfo->subscribe);
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
    if (!JsObjectToString(env, args, "name", true, name) ||
        !JsObjectToString(env, args, "description", true, description)) {
        EDMLOGE("ParseEnterpriseInfo param error");
        return false;
    }
    EDMLOGD("ParseEnterpriseInfo name %{public}s ", name.c_str());
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

bool AdminManager::ParseManagedEvent(napi_env env, std::vector<uint32_t> &managedEvent, napi_value args)
{
    bool isArray = false;
    if (napi_is_array(env, args, &isArray) != napi_ok || !isArray) {
        return false;
    }
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

napi_value AdminManager::AuthorizeAdmin(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AuthorizeAdmin called.");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "AuthorizeAdmin";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::STRING};
    addonMethodSign.methodAttribute = MethodAttribute::OPERATE_ADMIN;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeAuthorizeAdmin, NativeVoidCallbackComplete);
}

void AdminManager::NativeAuthorizeAdmin(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeAuthorizeAdmin called.");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbakInfo = static_cast<AdapterAddonData *>(data);
    asyncCallbakInfo->ret = EnterpriseDeviceMgrProxy::GetInstance()->AuthorizeAdmin(asyncCallbakInfo->data);
}

napi_value AdminManager::SetDelegatedPolicies(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetDelegatedPolicies called.");
    auto convertPolicies2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
        std::vector<std::string> policies;
        bool isParseOk = ParseStringArray(env, policies, argv);
        if (!isParseOk) {
            return false;
        }
        data.WriteStringVector(policies);
        return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetDelegatedPolicies";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::STRING, EdmAddonCommonType::CUSTOM};
    addonMethodSign.methodAttribute = MethodAttribute::OPERATE_ADMIN;
    addonMethodSign.argsConvert = {nullptr, nullptr, convertPolicies2Data};

    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }

    int32_t ret = EnterpriseDeviceMgrProxy::GetInstance()->SetDelegatedPolicies(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value AdminManager::GetDelegatedPolicies(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDelegatedPolicies called.");
    return GetDelegatedPolicies(env, info, EdmInterfaceCode::GET_DELEGATED_POLICIES);
}

napi_value AdminManager::GetDelegatedBundleNames(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDelegatedBundleNames called.");
    return GetDelegatedPolicies(env, info, EdmInterfaceCode::GET_DELEGATED_BUNDLE_NAMES);
}

napi_value AdminManager::GetDelegatedPolicies(napi_env env, napi_callback_info info, uint32_t code)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetDelegatedPolicies";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::STRING};
    addonMethodSign.methodAttribute = MethodAttribute::OPERATE_ADMIN;
    
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }

    std::vector<std::string> policies;
    int32_t ret = EnterpriseDeviceMgrProxy::GetInstance()->GetDelegatedPolicies(adapterAddonData.data, code, policies);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_array(env, &result));
    ConvertStringVectorToJS(env, policies, result);
    return result;
}

napi_value AdminManager::GetAdmins(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetAdmins";
    addonMethodSign.methodAttribute = MethodAttribute::OPERATE_ADMIN;
    auto adapterAddonData = new (std::nothrow) AsyncGetAdminsCallbackInfo();
    if (adapterAddonData == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncGetAdminsCallbackInfo> callbackPtr{adapterAddonData};
    if (JsObjectToData(env, info, addonMethodSign, adapterAddonData) == nullptr) {
        return nullptr;
    }
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, adapterAddonData, "GetAdmins", NativeGetAdmins, NativeGetAdminsComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

napi_value AdminManager::StartAdminProvision(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_StartAdminProvision called.");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_FOUR, "parameter count error");
    AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter admin error");
    int32_t jsAdminType;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, jsAdminType, argv[ARR_INDEX_ONE]),
        "parameter adminType error");
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, argv[ARR_INDEX_TWO], stageMode);
    ASSERT_AND_THROW_PARAM_ERROR(env, status == napi_ok && stageMode,
        "Parse param context failed, must be a context of stageMode.");
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[ARR_INDEX_TWO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, context != nullptr, "Parse param context failed, must not be nullptr.");
    auto uiAbilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    ASSERT_AND_THROW_PARAM_ERROR(env, uiAbilityContext != nullptr,
        "Parse param context failed, must be UIAbilityContext.");
    std::map<std::string, std::string> parameters;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseMapStringAndString(env, parameters, argv[ARR_INDEX_THREE]),
        "parameter parameters error");
    int32_t adminType = JsAdminTypeToAdminType(jsAdminType);
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckByodParams(elementName, uiAbilityContext->GetBundleName(), adminType,
        parameters), "byod parameters error");
    std::string bundleName;
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->CheckAndGetAdminProvisionInfo(elementName, bundleName);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    AppExecFwk::ElementName adminProvisionElement("", bundleName, ADMIN_PROVISIONING_ABILITY_NAME);
    AAFwk::Want want;
    want.SetElement(adminProvisionElement);
    want.SetParam("bundleName", elementName.GetBundleName());
    want.SetParam("abilityName", elementName.GetAbilityName());
    for (auto &param : parameters) {
        want.SetParam(param.first, param.second);
    }
    auto token = uiAbilityContext->GetToken();
    ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
    }
    return nullptr;
}

bool AdminManager::CheckByodParams(AppExecFwk::ElementName elementName, const std::string &callerBundleName,
    int32_t adminType, std::map<std::string, std::string> &parameters)
{
    if (elementName.GetBundleName().empty() || elementName.GetAbilityName().empty()) {
        EDMLOGE("CheckByodParams: bundleName or abilityName is empty.");
        return false;
    }
    if (callerBundleName != elementName.GetBundleName()) {
        EDMLOGE("CheckByodParams: callerBundleName is not the input bundleName.");
        return false;
    }
    if (adminType != static_cast<int32_t>(AdminType::BYOD)) {
        EDMLOGE("CheckByodParams: admin type is not byod.");
        return false;
    }
    if (parameters.size() > MAX_ADMINPROVISION_PARAM_NUM) {
        EDMLOGE("CheckByodParams: parameters size is too much. Max is ten.");
        return false;
    }
    if (parameters.find(ACTIVATEID) == parameters.end()) {
        EDMLOGE("CheckByodParams: activateId is not exist.");
        return false;
    }
    size_t activateIdLen = parameters[ACTIVATEID].length();
    if (activateIdLen < MIN_ACTIVATEID_LEN || activateIdLen > MAX_ACTIVATEID_LEN) {
        EDMLOGE("CheckByodParams:the length of activateId is not in [32, 256].The length is %{public}d", activateIdLen);
        return false;
    }
    if (parameters.find(CUSTOMIZEDINFO) != parameters.end() &&
        parameters[CUSTOMIZEDINFO].length() > MAX_CUSTOMIZEDINFO_LEN) {
        EDMLOGE("CheckByodParams: the length of customizedInfo is more than 10240.");
        return false;
    }
    return true;
}

void AdminManager::CreateAdminTypeObject(napi_env env, napi_value value)
{
    napi_value nNomal;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AdminType::NORMAL), &nNomal));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ADMIN_TYPE_NORMAL", nNomal));
    napi_value nSuper;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(AdminType::ENT), &nSuper));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ADMIN_TYPE_SUPER", nSuper));
    napi_value nByod;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, JS_BYOD_TYPE, &nByod));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ADMIN_TYPE_BYOD", nByod));
}

void AdminManager::CreateManagedEventObject(napi_env env, napi_value value)
{
    napi_value nBundleAdded;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_uint32(env, static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED), &nBundleAdded));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_BUNDLE_ADDED", nBundleAdded));
    napi_value nBundleRemoved;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_uint32(env, static_cast<uint32_t>(ManagedEvent::BUNDLE_REMOVED), &nBundleRemoved));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_BUNDLE_REMOVED", nBundleRemoved));
    napi_value nAppStart;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(ManagedEvent::APP_START), &nAppStart));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_APP_START", nAppStart));
    napi_value nAppStop;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(ManagedEvent::APP_STOP), &nAppStop));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_APP_STOP", nAppStop));
    napi_value nSystemUpdate;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(ManagedEvent::SYSTEM_UPDATE),
        &nSystemUpdate));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_SYSTEM_UPDATE", nSystemUpdate));
    napi_value nUserAdded;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(ManagedEvent::USER_ADDED),
        &nUserAdded));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_ACCOUNT_ADDED", nUserAdded));
    napi_value nUserSwitched;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(ManagedEvent::USER_SWITCHED),
        &nUserSwitched));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_ACCOUNT_SWITCHED", nUserSwitched));
    napi_value nUserRemoved;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(ManagedEvent::USER_REMOVED),
        &nUserRemoved));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MANAGED_EVENT_ACCOUNT_REMOVED", nUserRemoved));
}

void AdminManager::CreateRunningModeObject(napi_env env, napi_value value)
{
    napi_value nDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(RunningMode::DEFAULT), &nDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DEFAULT", nDefault));
    napi_value nMultiUser;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(RunningMode::MULTI_USER), &nMultiUser));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "MULTI_USER", nMultiUser));
}

napi_value AdminManager::GetSuperAdmin(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetSuperAdmin called");
    auto asyncCallbackInfo = new (std::nothrow) AsyncGetSuperAdminCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncGetSuperAdminCallbackInfo> callbackPtr{asyncCallbackInfo};
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "GetSuperAdmin", NativeGetSuperAdmin, NativeGetSuperAdminComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void AdminManager::NativeGetSuperAdmin(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetSuperAdmin called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncGetSuperAdminCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetSuperAdminCallbackInfo *>(data);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    asyncCallbackInfo->ret = proxy->GetSuperAdmin(asyncCallbackInfo->bundleName, asyncCallbackInfo->abilityName);
}

void AdminManager::NativeGetSuperAdminComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncGetSuperAdminCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        EDMLOGD("asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_value accountValue = ConvertWantToJs(env, asyncCallbackInfo->bundleName,
                asyncCallbackInfo->abilityName);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, accountValue);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
        }
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

void AdminManager::NativeGetAdmins(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetAdmins called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncGetAdminsCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetAdminsCallbackInfo *>(data);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    asyncCallbackInfo->ret = proxy->GetAdmins(asyncCallbackInfo->data, asyncCallbackInfo->wants);
}

void AdminManager::NativeGetAdminsComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncGetAdminsCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        EDMLOGD("asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_value admins = ConvertWantToJsWithType(env, asyncCallbackInfo->wants);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, admins);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
        }
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

napi_value AdminManager::ConvertWantToJs(napi_env env, const std::string &bundleName,
    const std::string &abilityName)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    napi_value bundleNameToJs = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, bundleName.c_str(), NAPI_AUTO_LENGTH, &bundleNameToJs));
    NAPI_CALL(env, napi_set_named_property(env, result, "bundleName", bundleNameToJs));
    napi_value abilityNameToJs = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, abilityName.c_str(), NAPI_AUTO_LENGTH, &abilityNameToJs));
    NAPI_CALL(env, napi_set_named_property(env, result, "abilityName", abilityNameToJs));
    return result;
}

napi_value AdminManager::ConvertWantToJsWithType(napi_env env, std::vector<std::shared_ptr<AAFwk::Want>> &wants)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_array(env, &result));
    size_t idx = 0;
    for (std::shared_ptr<AAFwk::Want> want : wants) {
        std::string bundleName = want->GetStringParam("bundleName");
        std::string abilityName = want->GetStringParam("abilityName");
        int32_t adminType = want->GetIntParam("adminType", -1);
        if (bundleName.empty() || abilityName.empty() || adminType == -1) {
            napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
            return nullptr;
        }
        napi_value wantItem = ConvertWantToJs(env, bundleName, abilityName);
        if (wantItem == nullptr) {
            napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
            return nullptr;
        }
        napi_value parameters = nullptr;
        NAPI_CALL(env, napi_create_object(env, &parameters));
        napi_value adminTypeToJs = nullptr;
        NAPI_CALL(env, napi_create_int32(env, AdminTypeToJsAdminType(adminType), &adminTypeToJs));
        NAPI_CALL(env, napi_set_named_property(env, parameters, "adminType", adminTypeToJs));
        NAPI_CALL(env, napi_set_named_property(env, wantItem, "parameters", parameters));
        NAPI_CALL(env, napi_set_element(env, result, idx, wantItem));
    }
    return result;
}

napi_value AdminManager::Init(napi_env env, napi_value exports)
{
    napi_value nAdminType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nAdminType));
    CreateAdminTypeObject(env, nAdminType);

    napi_value nManagedEvent = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nManagedEvent));
    CreateManagedEventObject(env, nManagedEvent);

    napi_value nRunningMode = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nRunningMode));
    CreateRunningModeObject(env, nRunningMode);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("enableAdmin", EnableAdmin),
        DECLARE_NAPI_FUNCTION("disableAdmin", DisableAdmin),
        DECLARE_NAPI_FUNCTION("disableSuperAdmin", DisableSuperAdmin),
        DECLARE_NAPI_FUNCTION("isAdminEnabled", IsAdminEnabled),
        DECLARE_NAPI_FUNCTION("getEnterpriseInfo", GetEnterpriseInfo),
        DECLARE_NAPI_FUNCTION("setEnterpriseInfo", SetEnterpriseInfo),
        DECLARE_NAPI_FUNCTION("isSuperAdmin", IsSuperAdmin),
        DECLARE_NAPI_FUNCTION("subscribeManagedEvent", SubscribeManagedEvent),
        DECLARE_NAPI_FUNCTION("unsubscribeManagedEvent", UnsubscribeManagedEvent),
        DECLARE_NAPI_FUNCTION("authorizeAdmin", AuthorizeAdmin),
        DECLARE_NAPI_FUNCTION("subscribeManagedEventSync", SubscribeManagedEventSync),
        DECLARE_NAPI_FUNCTION("unsubscribeManagedEventSync", UnsubscribeManagedEventSync),
        DECLARE_NAPI_FUNCTION("getSuperAdmin", GetSuperAdmin),
        DECLARE_NAPI_FUNCTION("setDelegatedPolicies", SetDelegatedPolicies),
        DECLARE_NAPI_FUNCTION("getDelegatedPolicies", GetDelegatedPolicies),
        DECLARE_NAPI_FUNCTION("getDelegatedBundleNames", GetDelegatedBundleNames),
        DECLARE_NAPI_FUNCTION("startAdminProvision", StartAdminProvision),
        DECLARE_NAPI_FUNCTION("getAdmins", GetAdmins),
        DECLARE_NAPI_FUNCTION("replaceSuperAdmin", ReplaceSuperAdmin),
        DECLARE_NAPI_FUNCTION("setAdminRunningMode", SetAdminRunningMode),

        DECLARE_NAPI_PROPERTY("AdminType", nAdminType),
        DECLARE_NAPI_PROPERTY("ManagedEvent", nManagedEvent),
        DECLARE_NAPI_PROPERTY("RunningMode", nRunningMode),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value AdminManager::SubscribeManagedEventSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("SubscribeManagedEvent called");
    return HandleManagedEventSync(env, info, true);
}

napi_value AdminManager::UnsubscribeManagedEventSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("UnsubscribeManagedEvent called");
    return HandleManagedEventSync(env, info, false);
}

napi_value AdminManager::HandleManagedEventSync(napi_env env, napi_callback_info info, bool subscribe)
{
    auto convertEvents2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
        std::vector<uint32_t> managedEvent;
        bool isParseOk = ParseManagedEvent(env, managedEvent, argv);
        if (!isParseOk) {
            return false;
        }
        data.WriteUInt32Vector(managedEvent);
        return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "HandleManagedEventSync";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM};
    addonMethodSign.methodAttribute = MethodAttribute::OPERATE_ADMIN;
    addonMethodSign.argsConvert = {nullptr, convertEvents2Data};
    
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }

    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    int32_t ret = proxy->HandleManagedEvent(adapterAddonData.data, subscribe);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

static napi_module g_edmServiceModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = AdminManager::Init,
    .nm_modname = "enterprise.adminManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void EdmServiceRegister()
{
    napi_module_register(&g_edmServiceModule);
}
