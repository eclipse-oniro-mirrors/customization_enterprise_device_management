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
#include "system_manager_addon.h"

#include "securec.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "napi_edm_adapter.h"

using namespace OHOS::EDM;

void SystemManagerAddon::AddFunctionsToExports(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("setNTPServer", SetNTPServer),
        DECLARE_NAPI_FUNCTION("getNTPServer", GetNTPServer),
        DECLARE_NAPI_FUNCTION("setOtaUpdatePolicy", SetOTAUpdatePolicy),
        DECLARE_NAPI_FUNCTION("getOtaUpdatePolicy", GetOTAUpdatePolicy),
        DECLARE_NAPI_FUNCTION("notifyUpdatePackages", NotifyUpdatePackages),
        DECLARE_NAPI_FUNCTION("getUpdateResult", GetUpgradeResult),
        DECLARE_NAPI_FUNCTION("getUpdateAuthData", GetUpdateAuthData),
        DECLARE_NAPI_FUNCTION("setAutoUnlockAfterReboot", SetAutoUnlockAfterReboot),
        DECLARE_NAPI_FUNCTION("getAutoUnlockAfterReboot", GetAutoUnlockAfterReboot),
        DECLARE_NAPI_FUNCTION("setInstallLocalEnterpriseAppEnabled", SetInstallLocalEnterpriseAppEnabled),
        DECLARE_NAPI_FUNCTION("getInstallLocalEnterpriseAppEnabled", GetInstallLocalEnterpriseAppEnabled),
        DECLARE_NAPI_FUNCTION("addDisallowedNearLinkProtocols", AddDisallowedNearlinkProtocols),
        DECLARE_NAPI_FUNCTION("getDisallowedNearLinkProtocols", GetDisallowedNearlinkProtocols),
        DECLARE_NAPI_FUNCTION("removeDisallowedNearLinkProtocols", RemoveDisallowedNearlinkProtocols),
        DECLARE_NAPI_FUNCTION("startCollectLog", StartCollectLog),
        DECLARE_NAPI_FUNCTION("finishLogCollected", FinishLogCollected),
        DECLARE_NAPI_FUNCTION("addKeyEventPolicies", AddKeyEventPolicies),
        DECLARE_NAPI_FUNCTION("removeKeyEventPolicies", RemoveKeyEventPolicies),
        DECLARE_NAPI_FUNCTION("getKeyEventPolicies", GetKeyEventPolicies),
        DECLARE_NAPI_FUNCTION("setActivationLockDisabled", SetActivationLockDisabled),
        DECLARE_NAPI_FUNCTION("isActivationLockDisabled", IsActivationLockDisabled),
    };
    NAPI_CALL_RETURN_VOID(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
}

void SystemManagerAddon::AddEnumsToExports(napi_env env, napi_value exports)
{
    napi_value nPolicyType = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nPolicyType));
    CreatePolicyTypeObject(env, nPolicyType);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "PolicyType", nPolicyType));

    napi_value nPackageType = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nPackageType));
    CreatePackageTypeObject(env, nPackageType);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "PackageType", nPackageType));

    napi_value nUpgradeStatus = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nUpgradeStatus));
    CreateUpgradeStatusObject(env, nUpgradeStatus);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "UpdateStatus", nUpgradeStatus));

    napi_value nProtocol = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nProtocol));
    CreateProtocolObject(env, nProtocol);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "NearLinkProtocol", nProtocol));

    napi_value nKeyCode = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nKeyCode));
    CreateKeyCodeObject(env, nKeyCode);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "KeyCode", nKeyCode));

    napi_value nKeyPolicy = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nKeyPolicy));
    CreateKeyPolicyObject(env, nKeyPolicy);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "KeyPolicy", nKeyPolicy));

    napi_value nKeyAction = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nKeyAction));
    CreateKeyActionObject(env, nKeyAction);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "KeyAction", nKeyAction));
}

napi_value SystemManagerAddon::Init(napi_env env, napi_value exports)
{
    AddFunctionsToExports(env, exports);
    AddEnumsToExports(env, exports);
    
    return exports;
}

void SystemManagerAddon::CreateKeyCodeObject(napi_env env, napi_value value)
{
    napi_value nPower;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyCode::POWER), &nPower));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "POWER", nPower));
    napi_value nVolumeUp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyCode::VOLUME_UP), &nVolumeUp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "VOLUME_UP", nVolumeUp));
    napi_value nVolumeDown;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyCode::VOLUME_DOWN), &nVolumeDown));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "VOLUME_DOWN", nVolumeDown));
    napi_value nBack;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyCode::BACK), &nBack));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "BACK", nBack));
    napi_value nHome;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyCode::HOME), &nHome));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "HOME", nHome));
    napi_value nRecent;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyCode::RECENT), &nRecent));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "RECENT", nRecent));
}

void SystemManagerAddon::CreateKeyActionObject(napi_env env, napi_value value)
{
    napi_value nUnknown;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyAction::UNKNOWN), &nUnknown));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNKNOWN", nUnknown));
    napi_value nDown;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyAction::DOWN), &nDown));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DOWN", nDown));
    napi_value nUp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyAction::UP), &nUp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UP", nUp));
}

void SystemManagerAddon::CreateKeyPolicyObject(napi_env env, napi_value value)
{
    napi_value nInterception;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyPolicy::INTERCEPTION), &nInterception));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "INTERCEPTION", nInterception));
    napi_value nCustom;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(KeyPolicy::CUSTOM), &nCustom));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "CUSTOM", nCustom));
}

void SystemManagerAddon::CreatePolicyTypeObject(napi_env env, napi_value value)
{
    napi_value nDefault;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(UpdatePolicyType::DEFAULT), &nDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DEFAULT", nDefault));
    napi_value nProhibit;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(UpdatePolicyType::PROHIBIT), &nProhibit));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PROHIBIT", nProhibit));
    napi_value nUpdateToSpecificVersion;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(UpdatePolicyType::UPDATE_TO_SPECIFIC_VERSION), &nUpdateToSpecificVersion));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UPDATE_TO_SPECIFIC_VERSION",
        nUpdateToSpecificVersion));
    napi_value nWindows;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(UpdatePolicyType::WINDOWS), &nWindows));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WINDOWS", nWindows));
    napi_value nPostpone;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(UpdatePolicyType::POSTPONE), &nPostpone));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "POSTPONE", nPostpone));
}

void SystemManagerAddon::CreatePackageTypeObject(napi_env env, napi_value value)
{
    napi_value nFirmware;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(PackageType::FIRMWARE), &nFirmware));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FIRMWARE", nFirmware));
}

void SystemManagerAddon::CreateUpgradeStatusObject(napi_env env, napi_value value)
{
    napi_value nNoUpgradePackage;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(UpgradeStatus::NO_UPGRADE_PACKAGE), &nNoUpgradePackage));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "NO_UPDATE_PACKAGE", nNoUpgradePackage));

    napi_value nUpgradeWaiting;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(UpgradeStatus::UPGRADE_WAITING), &nUpgradeWaiting));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UPDATE_WAITING", nUpgradeWaiting));

    napi_value nUpgrading;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(UpgradeStatus::UPGRADING), &nUpgrading));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UPDATING", nUpgrading));

    napi_value nUpgradeFailure;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(UpgradeStatus::UPGRADE_FAILURE), &nUpgradeFailure));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UPDATE_FAILURE", nUpgradeFailure));

    napi_value nUpgradeSuccess;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(UpgradeStatus::UPGRADE_SUCCESS), &nUpgradeSuccess));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UPDATE_SUCCESS", nUpgradeSuccess));
}

napi_value SystemManagerAddon::SetNTPServer(napi_env env, napi_callback_info info)
{
    EDMLOGI("SetNTPServer Addon called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetNTPServer";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::STRING};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->SetNTPServer(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SetNTPServer failed!");
    }
    return nullptr;
}

napi_value SystemManagerAddon::GetNTPServer(napi_env env, napi_callback_info info)
{
    EDMLOGI("GetNTPServer Addon called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetNTPServer";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    std::string ntpParm;
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->GetNTPServer(adapterAddonData.data, ntpParm);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("GetNTPServer failed!");
        return nullptr;
    }
    napi_value ntpServerString = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, ntpParm.c_str(), ntpParm.size(), &ntpServerString));
    return ntpServerString;
}

napi_value SystemManagerAddon::SetOTAUpdatePolicy(napi_env env, napi_callback_info info)
{
    auto convertupdatePolicy2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
            UpdatePolicy updatePolicy;
            std::string errorMsg;
            if (!JsObjToUpdatePolicy(env, argv, updatePolicy, errorMsg)) {
                EDMLOGE("%{public}s", errorMsg.c_str());
                return false;
            }
            UpdatePolicyUtils::WriteUpdatePolicy(data, updatePolicy);
            return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetOTAUpdatePolicy";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {nullptr, convertupdatePolicy2Data};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    std::string message;
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->SetOTAUpdatePolicy(adapterAddonData.data, message);
    if (ret == EdmReturnErrCode::PARAM_ERROR) {
        napi_throw(env, CreateError(env, ret, message));
    } else if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value SystemManagerAddon::GetOTAUpdatePolicy(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetOTAUpdatePolicy";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    UpdatePolicy updatePolicy;
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->GetOTAUpdatePolicy(adapterAddonData.data, updatePolicy);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return ConvertUpdatePolicyToJs(env, updatePolicy);
}

napi_value SystemManagerAddon::NotifyUpdatePackages(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_NotifyUpdatePackages called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_object), "parameter policy error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncNotifyUpdatePackagesCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncNotifyUpdatePackagesCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "IsAdminEnabled::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToUpgradePackageInfo(env, argv[ARR_INDEX_ONE],
        asyncCallbackInfo->packageInfo), "parameter packageInfo parse error");

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "NotifyUpdatePackages",
        NativeNotifyUpdatePackages, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void SystemManagerAddon::NativeNotifyUpdatePackages(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeNotifyUpdatePackages called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncNotifyUpdatePackagesCallbackInfo *>(data);
    auto proxy = SystemManagerProxy::GetSystemManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbackInfo->ret = proxy->NotifyUpdatePackages(asyncCallbackInfo->elementName, asyncCallbackInfo->packageInfo,
        asyncCallbackInfo->innerCodeMsg);
}

napi_value SystemManagerAddon::GetUpgradeResult(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetOTAUpdatePolicy called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "parameter version error");

    auto asyncCallbackInfo = new (std::nothrow) AsyncGetUpgradeResultCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncGetUpgradeResultCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "IsAdminEnabled::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->version, argv[ARR_INDEX_ONE]),
        "version param error");

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "GetUpgradeResult", NativeGetUpgradeResult,
        NativeUpgradeResultComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

napi_value SystemManagerAddon::GetUpdateAuthData(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetUpdateAuthData called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetUpdateAuthData";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeGetUpdateAuthData, NativeStringCallbackComplete);
}

void SystemManagerAddon::NativeGetUpgradeResult(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetUpgradeResult called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncGetUpgradeResultCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetUpgradeResultCallbackInfo *>(data);
    auto proxy = SystemManagerProxy::GetSystemManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbackInfo->ret = proxy->GetUpgradeResult(asyncCallbackInfo->elementName, asyncCallbackInfo->version,
        asyncCallbackInfo->upgradeResult);
}

void SystemManagerAddon::NativeGetUpdateAuthData(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetUpdateAuthData called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbakInfo = static_cast<AdapterAddonData *>(data);
    asyncCallbakInfo->ret = SystemManagerProxy::GetSystemManagerProxy()->GetUpdateAuthData(asyncCallbakInfo->data,
        asyncCallbakInfo->stringRet);
}

void SystemManagerAddon::NativeUpgradeResultComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncGetUpgradeResultCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        EDMLOGD("asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_value result = ConvertUpdateResultToJs(env, asyncCallbackInfo->upgradeResult);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, result);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
        }
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

napi_value SystemManagerAddon::SetAutoUnlockAfterReboot(napi_env env, napi_callback_info info)
{
#ifdef FEATURE_PC_ONLY
    EDMLOGI("SystemManagerAddon::SetAutoUnlockAfterReboot called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetAutoUnlockAfterReboot";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->SetAutoUnlockAfterReboot(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SystemManagerAddon::SetAutoUnlockAfterReboot failed!");
    }
    return nullptr;
#else
    EDMLOGW("SystemManagerAddon::SetAutoUnlockAfterReboot Unsupported Capabilities");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value SystemManagerAddon::GetAutoUnlockAfterReboot(napi_env env, napi_callback_info info)
{
#ifdef FEATURE_PC_ONLY
    EDMLOGI("SystemManagerAddon::GetAutoUnlockAfterReboot called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetAutoUnlockAfterReboot";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    bool isAllowed = false;
    int32_t ret =
        SystemManagerProxy::GetSystemManagerProxy()->GetAutoUnlockAfterReboot(adapterAddonData.data, isAllowed);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SystemManagerAddon::GetAutoUnlockAfterReboot failed!");
        return nullptr;
    }
    napi_value resultBool = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isAllowed, &resultBool));
    return resultBool;
#else
    EDMLOGW("SystemManagerAddon::GetAutoUnlockAfterReboot Unsupported Capabilities");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

bool SystemManagerAddon::JsObjToUpdatePolicy(napi_env env, napi_value object, UpdatePolicy &updatePolicy,
    std::string &errorMsg)
{
    int32_t policyType = -1;
    if (!JsObjectToInt(env, object, "policyType", true, policyType) ||
        !UpdatePolicyUtils::ProcessUpdatePolicyType(policyType, updatePolicy.type)) {
        errorMsg = "the property 'policyType' in type 'OtaUpdatePolicy' is necessary";
        return false;
    }

    if (!JsObjectToString(env, object, "version", true, updatePolicy.version)) {
        errorMsg = "the property 'version' in type 'OtaUpdatePolicy' is necessary";
        return false;
    }

    if (!JsObjectToLong(env, object, "latestUpdateTime", false, updatePolicy.installTime.latestUpdateTime)) {
        errorMsg = "the property 'latestUpdateTime' in type 'OtaUpdatePolicy' is check failed";
        return false;
    }

    if (!JsObjectToLong(env, object, "installStartTime", updatePolicy.type == UpdatePolicyType::WINDOWS,
        updatePolicy.installTime.installWindowStart)) {
        errorMsg = "the property 'installStartTime' in type 'OtaUpdatePolicy' is check failed";
        return false;
    }

    if (!JsObjectToLong(env, object, "installEndTime", updatePolicy.type == UpdatePolicyType::WINDOWS,
        updatePolicy.installTime.installWindowEnd)) {
        errorMsg = "the property 'installEndTime' in type 'OtaUpdatePolicy' is check failed";
        return false;
    }

    if (!JsObjectToLong(env, object, "delayUpdateTime", updatePolicy.type == UpdatePolicyType::POSTPONE,
        updatePolicy.installTime.delayUpdateTime)) {
        errorMsg = "the property 'delayUpdateTime' in type 'OtaUpdatePolicy' is check failed";
        return false;
    }
    if (!JsDisableSystemOtaUpdateToUpdatePolicy(env, object, "disableSystemOtaUpdate", updatePolicy.otaPolicyType)) {
        errorMsg = "the property 'disableSystemOtaUpdate' in type 'OtaUpdatePolicy' is check failed";
        return false;
    }
    return true;
}

bool SystemManagerAddon::JsDisableSystemOtaUpdateToUpdatePolicy(napi_env env, napi_value object, const char *filedStr,
    OtaPolicyType &otaPolicyType)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, filedStr, &hasProperty) != napi_ok) {
        EDMLOGE("get js property failed.");
        return false;
    }
    if (!hasProperty) {
        otaPolicyType = OtaPolicyType::DEFAULT;
        return true;
    }
    napi_value prop = nullptr;
    bool res = false;
    if (!(napi_get_named_property(env, object, filedStr, &prop) == napi_ok && ParseBool(env, res, prop))) {
        EDMLOGE("get js ParseBool failed.");
        return false;
    }
    otaPolicyType = res ? OtaPolicyType::DISABLE_OTA : OtaPolicyType::ENABLE_OTA;
    return true;
}

napi_value SystemManagerAddon::ConvertUpdatePolicyToJs(napi_env env, const UpdatePolicy &updatePolicy)
{
    napi_value otaUpdatePolicy = nullptr;
    NAPI_CALL(env, napi_create_object(env, &otaUpdatePolicy));

    napi_value policyType = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(updatePolicy.type), &policyType));
    NAPI_CALL(env, napi_set_named_property(env, otaUpdatePolicy, "policyType", policyType));

    napi_value version = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, updatePolicy.version.c_str(), updatePolicy.version.length(), &version));
    NAPI_CALL(env, napi_set_named_property(env, otaUpdatePolicy, "version", version));

    napi_value latestUpdateTime = nullptr;
    NAPI_CALL(env, napi_create_int64(env, updatePolicy.installTime.latestUpdateTime, &latestUpdateTime));
    NAPI_CALL(env, napi_set_named_property(env, otaUpdatePolicy, "latestUpdateTime", latestUpdateTime));

    napi_value delayUpdateTime = nullptr;
    NAPI_CALL(env, napi_create_int64(env, updatePolicy.installTime.delayUpdateTime, &delayUpdateTime));
    NAPI_CALL(env, napi_set_named_property(env, otaUpdatePolicy, "delayUpdateTime", delayUpdateTime));

    napi_value installStartTime = nullptr;
    NAPI_CALL(env, napi_create_int64(env, updatePolicy.installTime.installWindowStart, &installStartTime));
    NAPI_CALL(env, napi_set_named_property(env, otaUpdatePolicy, "installStartTime", installStartTime));

    napi_value installEndTime = nullptr;
    NAPI_CALL(env, napi_create_int64(env, updatePolicy.installTime.installWindowEnd, &installEndTime));
    NAPI_CALL(env, napi_set_named_property(env, otaUpdatePolicy, "installEndTime", installEndTime));

    napi_value disableSystemOtaUpdate = nullptr;
    bool isDisableSystemOtaUpdate = false;
    if (updatePolicy.otaPolicyType == OtaPolicyType::DISABLE_OTA) {
        isDisableSystemOtaUpdate = true;
    }
    NAPI_CALL(env, napi_get_boolean(env, isDisableSystemOtaUpdate, &disableSystemOtaUpdate));
    NAPI_CALL(env, napi_set_named_property(env, otaUpdatePolicy, "disableSystemOtaUpdate", disableSystemOtaUpdate));
    return otaUpdatePolicy;
}

bool SystemManagerAddon::JsObjToUpgradePackageInfo(napi_env env, napi_value object, UpgradePackageInfo &packageInfo)
{
    if (!JsObjectToString(env, object, "version", true, packageInfo.version)) {
        EDMLOGE("JsObjToUpgradePackageInfo version trans failed!");
        return false;
    }

    napi_value nPackages;
    if (!GetJsProperty(env, object, "packages", nPackages) || !ParsePackages(env, nPackages, packageInfo.packages)) {
        return false;
    }

    napi_value nDescription;
    if (GetJsProperty(env, object, "description", nDescription) &&
        !ParseDescription(env, nDescription, packageInfo.description)) {
        return false;
    }
    std::tuple<int, bool> charArrayProp = {EdmConstants::AUTH_INFO_MAX_SIZE, false};
    std::vector<char> ret;
    if (!JsObjectToCharArray(env, object, "authInfo", charArrayProp, ret)) {
        EDMLOGE("JsObjToUpgradePackageInfo authInfo trans failed!");
        return false;
    }
    if (ret.size() == 0) {
        return true;
    }
    errno_t err = memcpy_s(packageInfo.authInfo, sizeof(packageInfo.authInfo), ret.data(), ret.size());
    memset_s(ret.data(), ret.size(), 0, ret.size());
    if (err != EOK) {
        return false;
    }
    packageInfo.authInfoSize = ret.size() - 1;
    return true;
}

bool SystemManagerAddon::ParsePackages(napi_env env, napi_value object, std::vector<Package> &packages)
{
    bool isArray = false;
    if (napi_is_array(env, object, &isArray) != napi_ok || !isArray) {
        return false;
    }
    uint32_t len = 0;
    if (napi_get_array_length(env, object, &len) != napi_ok) {
        return false;
    }
    for (uint32_t i = 0; i < len; i++) {
        napi_value nPackage;
        if (napi_get_element(env, object, i, &nPackage) != napi_ok) {
            return false;
        }
        Package package;
        if (!ParsePackage(env, nPackage, package)) {
            return false;
        }
        packages.push_back(package);
    }
    return true;
}

bool SystemManagerAddon::ParsePackage(napi_env env, napi_value object, Package &package)
{
    int32_t type = static_cast<int32_t>(PackageType::UNKNOWN);
    if (!JsObjectToInt(env, object, "type", true, type)) {
        return false;
    }
    if (type != static_cast<int32_t>(PackageType::FIRMWARE)) {
        return false;
    }
    package.type = static_cast<PackageType>(type);
    return JsObjectToString(env, object, "path", true, package.path) &&
        JsObjectToInt(env, object, "fd", false, package.fd);
}

bool SystemManagerAddon::ParseDescription(napi_env env, napi_value object, PackageDescription &description)
{
    napi_value nNotify;
    if (GetJsProperty(env, object, "notify", nNotify)) {
        if (!JsObjectToString(env, nNotify, "installTips", false, description.notify.installTips) ||
            !JsObjectToString(env, nNotify, "installTipsDetails", false, description.notify.installTipsDetail)) {
            return false;
        }
    }
    return true;
}

napi_value SystemManagerAddon::ConvertUpdateResultToJs(napi_env env, const UpgradeResult &updateResult)
{
    napi_value nUpgradeResult = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nUpgradeResult));

    napi_value version = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, updateResult.version.c_str(), updateResult.version.length(), &version));
    NAPI_CALL(env, napi_set_named_property(env, nUpgradeResult, "version", version));

    napi_value status = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(updateResult.status), &status));
    NAPI_CALL(env, napi_set_named_property(env, nUpgradeResult, "status", status));

    napi_value nErrorInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nErrorInfo));

    napi_value errorCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, updateResult.errorCode, &errorCode));
    NAPI_CALL(env, napi_set_named_property(env, nErrorInfo, "code", errorCode));

    napi_value errorMessage = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, updateResult.errorMessage.c_str(), updateResult.errorMessage.length(),
        &errorMessage));
    NAPI_CALL(env, napi_set_named_property(env, nErrorInfo, "message", errorMessage));

    NAPI_CALL(env, napi_set_named_property(env, nUpgradeResult, "errorInfo", nErrorInfo));
    return nUpgradeResult;
}

napi_value SystemManagerAddon::SetInstallLocalEnterpriseAppEnabled(napi_env env, napi_callback_info info)
{
#ifdef FEATURE_PC_ONLY
    EDMLOGI("SystemManagerAddon::SetInstallLocalEnterpriseAppEnabled called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetInstallLocalEnterpriseAppEnabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret =
        SystemManagerProxy::GetSystemManagerProxy()->SetInstallLocalEnterpriseAppEnabled(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SystemManagerAddon::SetInstallLocalEnterpriseAppEnabled failed!");
    }
    return nullptr;
#else
    EDMLOGW("SystemManagerAddon::SetInstallLocalEnterpriseAppEnabled Unsupported Capabilities");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}
 
napi_value SystemManagerAddon::GetInstallLocalEnterpriseAppEnabled(napi_env env, napi_callback_info info)
{
#ifdef FEATURE_PC_ONLY
    EDMLOGI("SystemManagerAddon::GetInstallLocalEnterpriseAppEnabled called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetInstallLocalEnterpriseAppEnabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    bool isAllowedInstall = false;
    int32_t ret =
        SystemManagerProxy::GetSystemManagerProxy()->GetInstallLocalEnterpriseAppEnabled(adapterAddonData.data,
            isAllowedInstall);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SystemManagerAddon::GetInstallLocalEnterpriseAppEnabled failed!");
        return nullptr;
    }
    napi_value resultBool = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isAllowedInstall, &resultBool));
    return resultBool;
#else
    EDMLOGW("SystemManagerAddon::GetInstallLocalEnterpriseAppEnabled Unsupported Capabilities");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value SystemManagerAddon::AddDisallowedNearlinkProtocols(napi_env env, napi_callback_info info)
{
#if defined(FEATURE_PC_ONLY)
    EDMLOGI("NAPI_AddDisallowedNearlinkProtocols called");
    return AddOrRemoveDisallowedNearlinkProtocols(env, info, FuncOperateType::SET);
#else
    EDMLOGW("SystemManagerAddon::AddDisallowedNearlinkProtocols Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value SystemManagerAddon::GetDisallowedNearlinkProtocols(napi_env env, napi_callback_info info)
{
#if defined(FEATURE_PC_ONLY)
    EDMLOGI("NAPI_GetDisallowedNearlinkProtocols called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetDisallowedNearlinkProtocols";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::USERID};
    addonMethodSign.argsConvert = {nullptr, nullptr};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    std::vector<int32_t> protocols;
    int32_t retCode = SystemManagerProxy::GetSystemManagerProxy()->
        GetDisallowedNearlinkProtocols(adapterAddonData.data, protocols);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
        return nullptr;
    }
    napi_value jsList = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, protocols.size(), &jsList));
    for (size_t i = 0; i < protocols.size(); i++) {
        napi_value item;
        NAPI_CALL(env, napi_create_int32(env, protocols[i], &item));
        NAPI_CALL(env, napi_set_element(env, jsList, i, item));
    }
    return jsList;
#else
    EDMLOGW("SystemManagerAddon::GetDisallowedNearlinkProtocols Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value SystemManagerAddon::RemoveDisallowedNearlinkProtocols(napi_env env, napi_callback_info info)
{
#if defined(FEATURE_PC_ONLY)
    EDMLOGI("NAPI_RemoveDisallowedNearlinkProtocols called");
    return AddOrRemoveDisallowedNearlinkProtocols(env, info, FuncOperateType::REMOVE);
#else
    EDMLOGW("SystemManagerAddon::RemoveDisallowedNearlinkProtocols Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value SystemManagerAddon::AddOrRemoveDisallowedNearlinkProtocols(napi_env env, napi_callback_info info,
    FuncOperateType operateType)
{
#if defined(FEATURE_PC_ONLY)
    EDMLOGI("NAPI_AddOrRemoveDisallowedNearlinkProtocols called");
    auto convertNearlinkProtocol2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
        std::vector<int32_t> nearlinkProtocols;
        if (!ParseIntArray(env, nearlinkProtocols, argv)) {
            EDMLOGE("NAPI_AddOrRemoveDisallowedNearlinkProtocols ParseIntArray fail");
            return false;
        }
        data.WriteInt32Vector(nearlinkProtocols);
        return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "AddOrRemoveDisallowedNearlinkProtocols";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM, EdmAddonCommonType::USERID};
    addonMethodSign.argsConvert = {nullptr, convertNearlinkProtocol2Data, nullptr};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    int32_t retCode = SystemManagerProxy::GetSystemManagerProxy()->
        AddOrRemoveDisallowedNearlinkProtocols(adapterAddonData.data, operateType);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
#else
    EDMLOGW("SystemManagerAddon::AddOrRemoveDisallowedNearlinkProtocols Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
#endif
    return nullptr;
}

napi_value SystemManagerAddon::StartCollectLog(napi_env env, napi_callback_info info)
{
    EDMLOGI("SystemManagerAddon::StartCollectLog called");
#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncStartCollectLogCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncStartCollectLogCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "StartCollectLog::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "StartCollectLog",
        NativeStartCollectLog, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
#else
    EDMLOGW("SystemManagerAddon::StartCollectLog Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
void SystemManagerAddon::NativeStartCollectLog(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeStartCollectLog called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncStartCollectLogCallbackInfo *>(data);
    asyncCallbackInfo->ret =
        SystemManagerProxy::GetSystemManagerProxy()->StartCollectlog(asyncCallbackInfo->elementName);
}
#endif

napi_value SystemManagerAddon::FinishLogCollected(napi_env env, napi_callback_info info)
{
    EDMLOGI("SystemManagerAddon::FinishLogCollected called");
#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "FinishLogCollected";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    int32_t retCode = SystemManagerProxy::GetSystemManagerProxy()->FinishLogCollected(adapterAddonData.data);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
#else
    EDMLOGW("SystemManagerAddon::FinishLogCollected Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

void SystemManagerAddon::CreateProtocolObject(napi_env env, napi_value value)
{
    napi_value nSsap;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(NearlinkProtocol::SSAP), &nSsap));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SSAP", nSsap));
    napi_value nDataTransfer;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(NearlinkProtocol::DATA_TRANSFER),
    &nDataTransfer));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DATA_TRANSFER", nDataTransfer));
}

napi_value SystemManagerAddon::AddKeyEventPolicies(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddKeyEventPolicies called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter elementName error");
    std::vector<KeyCustomization> KeyCustomizations;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseKeyCustomizationArray(env, KeyCustomizations, argv[ARR_INDEX_ONE]),
        "Parameter KeyEventPolicys error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::string retMessage;
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->SetKeyEventPolicys(elementName,
        KeyCustomizations, retMessage);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value SystemManagerAddon::RemoveKeyEventPolicies(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveKeyEventPolicies called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter elementName error");
    std::vector<int32_t> Keyevents;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseIntArray(env, Keyevents, argv[ARR_INDEX_ONE]),
        "Parameter Keyevents error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->RemoveKeyEventPolicys(elementName, Keyevents);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value SystemManagerAddon::GetKeyEventPolicies(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetKeyEventPolicies called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter elementName error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto systemManagerProxy = SystemManagerProxy::GetSystemManagerProxy();
    std::vector<KeyCustomization> KeyCustomizations;
    int32_t ret = systemManagerProxy->GetKeyEventPolicys(elementName, KeyCustomizations);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiKeyCustomizations = nullptr;
    napi_create_array(env, &napiKeyCustomizations);
    ConvertKeyCustomizationVectorToJS(env, KeyCustomizations, napiKeyCustomizations);
    return napiKeyCustomizations;
}

bool SystemManagerAddon::CheckSetActivationLockDisabledParamType(napi_env env, size_t argc,
    napi_value* argv, bool &hascredential)
{
    if (!MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) || !MatchValueType(env, argv[ARR_INDEX_ONE],
        napi_boolean)) {
        EDMLOGE("CheckAddDisallowedRunningBundlesParamType admin or array type check failed");
        return false;
    }
    EDMLOGI("CheckAddDisallowedRunningBundlesParamType argc = %{public}zu", argc);
    if (argc == ARGS_SIZE_TWO) {
        hascredential = false;
        EDMLOGI("hasCallback = false;");
        return true;
    }
    hascredential = true;
    EDMLOGI("hascredential = true;");
    return MatchValueType(env, argv[ARR_INDEX_TWO], napi_string);
}
 	 
napi_value SystemManagerAddon::SetActivationLockDisabled(napi_env env, napi_callback_info info)
{
#if defined(FEATURE_PC_ONLY)
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    bool hascredential = false;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    auto asyncCallbackInfo = new (std::nothrow) AsyncActivationLockDisabledCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncActivationLockDisabledCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env,
        CheckSetActivationLockDisabledParamType(env, argc, argv, hascredential), "Parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, asyncCallbackInfo->isDisabled, argv[ARR_INDEX_ONE]),
        "Parameter isDisabled error");
    EDMLOGD("EnableAdmin::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (hascredential) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->credential, argv[ARR_INDEX_TWO]),
        "Parameter credential error");
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "SetActivationLockDisabled",
        NativeSetActivationLockDisabled, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
#else
    EDMLOGW("SystemManagerAddon::SetActivationLockDisabled Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

#if defined(FEATURE_PC_ONLY)
void SystemManagerAddon::NativeSetActivationLockDisabled(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetActivationLockDisable called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncActivationLockDisabledCallbackInfo *>(data);
    auto proxy = SystemManagerProxy::GetSystemManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbackInfo->ret = proxy->SetActivationLockDisabled(asyncCallbackInfo->elementName,
        asyncCallbackInfo->isDisabled, asyncCallbackInfo->credential);
}
#endif

napi_value SystemManagerAddon::IsActivationLockDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsPolicyDisabled called");
#if defined(FEATURE_PC_ONLY)
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncActivationLockDisabledCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncActivationLockDisabledCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "IsActivationLockDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "IsActivationLockDisabled", NativeIsActivationLockDisabled,
            NativeBoolCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
#else
    EDMLOGW("SystemManagerAddon::SetActivationLockDisabled Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

#if defined(FEATURE_PC_ONLY)
void SystemManagerAddon::NativeIsActivationLockDisabled(napi_env env, void *data)
{
    EDMLOGI("NativeActivationLockDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncActivationLockDisabledCallbackInfo *asyncCallbackInfo =
        static_cast<AsyncActivationLockDisabledCallbackInfo *>(data);
    auto proxy = SystemManagerProxy::GetSystemManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return;
    }
    asyncCallbackInfo->ret = proxy->IsActivationLockDisabled(asyncCallbackInfo->elementName,
        asyncCallbackInfo->boolRet);
}
#endif

static napi_module g_systemManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = SystemManagerAddon::Init,
    .nm_modname = "enterprise.systemManager",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void SystemManagerRegister()
{
    napi_module_register(&g_systemManagerModule);
}