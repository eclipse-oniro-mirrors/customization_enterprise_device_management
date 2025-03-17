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

napi_value SystemManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value nPolicyType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nPolicyType));
    CreatePolicyTypeObject(env, nPolicyType);

    napi_value nPackageType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nPackageType));
    CreatePackageTypeObject(env, nPackageType);

    napi_value nUpgradeStatus = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nUpgradeStatus));
    CreateUpgradeStatusObject(env, nUpgradeStatus);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setNTPServer", SetNTPServer),
        DECLARE_NAPI_FUNCTION("getNTPServer", GetNTPServer),
        DECLARE_NAPI_FUNCTION("setOtaUpdatePolicy", SetOTAUpdatePolicy),
        DECLARE_NAPI_FUNCTION("getOtaUpdatePolicy", GetOTAUpdatePolicy),
        DECLARE_NAPI_FUNCTION("notifyUpdatePackages", NotifyUpdatePackages),
        DECLARE_NAPI_FUNCTION("getUpdateResult", GetUpgradeResult),
        DECLARE_NAPI_FUNCTION("getUpdateAuthData", GetUpdateAuthData),

        DECLARE_NAPI_PROPERTY("PolicyType", nPolicyType),
        DECLARE_NAPI_PROPERTY("PackageType", nPackageType),
        DECLARE_NAPI_PROPERTY("UpdateStatus", nUpgradeStatus),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
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
        UpdatePolicyUtils::ClosePackagesFileHandle(asyncCallbackInfo->packageInfo.packages);
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
        UpdatePolicyUtils::ClosePackagesFileHandle(packageInfo.packages);
        return false;
    }

    napi_value nDescription;
    if (GetJsProperty(env, object, "description", nDescription) &&
        !ParseDescription(env, nDescription, packageInfo.description)) {
        UpdatePolicyUtils::ClosePackagesFileHandle(packageInfo.packages);
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