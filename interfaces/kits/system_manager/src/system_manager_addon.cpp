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
#include "system_manager_addon.h"
#include "edm_log.h"

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
        DECLARE_NAPI_FUNCTION("notifyUpgradePackages", NotifyUpgradePackages),
        DECLARE_NAPI_FUNCTION("getUpgradeResult", GetUpgradeResult),

        DECLARE_NAPI_PROPERTY("PolicyType", nPolicyType),
        DECLARE_NAPI_PROPERTY("PackageType", nPackageType),
        DECLARE_NAPI_PROPERTY("UpgradeStatus", nUpgradeStatus),
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
    napi_value nForceImmediate;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(UpdatePolicyType::FORCE_IMMEDIATE_UPDATE), &nForceImmediate));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FORCE_IMMEDIATE_UPDATE", nForceImmediate));
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
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "NO_UPGRADE_PACKAGE", nNoUpgradePackage));

    napi_value nUpgradeWaiting;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(UpgradeStatus::UPGRADE_WAITING), &nUpgradeWaiting));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UPGRADE_WAITING", nUpgradeWaiting));

    napi_value nUpgrading;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(UpgradeStatus::UPGRADING), &nUpgrading));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UPGRADING", nUpgrading));

    napi_value nUpgradeFailure;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(UpgradeStatus::UPGRADE_FAILURE), &nUpgradeFailure));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UPGRADE_FAILURE", nUpgradeFailure));

    napi_value nUpgradeSuccess;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(UpgradeStatus::UPGRADE_SUCCESS), &nUpgradeSuccess));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UPGRADE_SUCCESS", nUpgradeSuccess));
}

napi_value SystemManagerAddon::SetNTPServer(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetNTPServer called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "parameter string error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "GetNTPServer: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    std::string ntpParm;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, ntpParm, argv[ARR_INDEX_ONE]), "element name param error");
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->SetNTPServer(elementName, ntpParm);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SetNTPServer failed!");
    }
    return nullptr;
}

napi_value SystemManagerAddon::GetNTPServer(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetNTPServer called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "GetNTPServer: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    std::string ntpParm;
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->GetNTPServer(elementName, ntpParm);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("GetNTPServer failed!");
        return nullptr;
    }
    napi_value ntpServerString = nullptr;
    napi_create_string_utf8(env, ntpParm.c_str(), ntpParm.size(), &ntpServerString);
    return ntpServerString;
}

napi_value SystemManagerAddon::SetOTAUpdatePolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetOTAUpdatePolicy called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_object), "parameter policy error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetOTAUpdatePolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    UpdatePolicy updatePolicy;
    ASSERT_AND_THROW_PARAM_ERROR(
        env, JsObjToUpdatePolicy(env, argv[ARR_INDEX_ONE], updatePolicy), "parameter policy parse error");
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->SetOTAUpdatePolicy(elementName, updatePolicy);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value SystemManagerAddon::GetOTAUpdatePolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetOTAUpdatePolicy called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("GetOTAUpdatePolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    UpdatePolicy updatePolicy;
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->GetOTAUpdatePolicy(elementName, updatePolicy);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return ConvertUpdatePolicyToJs(env, updatePolicy);
}

napi_value SystemManagerAddon::NotifyUpgradePackages(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_NotifyUpgradePackages called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_object), "parameter policy error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("NotifyUpgradePackages: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    UpgradePackageInfo packageInfo;
    ASSERT_AND_THROW_PARAM_ERROR(
        env, JsObjToUpgradePackageInfo(env, argv[ARR_INDEX_ONE], packageInfo), "parameter packageInfo parse error");
    int32_t ret = SystemManagerProxy::GetSystemManagerProxy()->NotifyUpgradePackages(elementName, packageInfo);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
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

bool SystemManagerAddon::JsObjToUpdatePolicy(napi_env env, napi_value object, UpdatePolicy &updatePolicy)
{
    int32_t policyType = -1;
    if (!JsObjectToInt(env, object, "policyType", true, policyType) ||
        !UpdatePolicyUtils::ProcessUpdatePolicyType(policyType, updatePolicy.type)) {
        EDMLOGE("SetOTAUpdatePolicy JsObjToUpdatePolicy updateType trans failed!");
        return false;
    }

    if (!JsObjectToString(env, object, "version", true, updatePolicy.version)) {
        EDMLOGE("SetOTAUpdatePolicy JsObjToUpdatePolicy version trans failed!");
        return false;
    }

    if (!JsObjectToLong(env, object, "latestUpdateTime", false, updatePolicy.installTime.latestUpdateTime)) {
        EDMLOGE("SetOTAUpdatePolicy JsObjToUpdateTime latestUpdateTime trans failed!");
        return false;
    }

    if (!JsObjectToLong(env, object, "delayUpdateTime", false, updatePolicy.installTime.delayUpdateTime)) {
        EDMLOGE("SetOTAUpdatePolicy JsObjToUpdateTime delayUpdateTime trans failed!");
        return false;
    }

    if (!JsObjectToLong(env, object, "installStartTime", false, updatePolicy.installTime.installWindowStart)) {
        EDMLOGE("SetOTAUpdatePolicy JsObjToUpdateTime installStartTime trans failed!");
        return false;
    }

    if (!JsObjectToLong(env, object, "installEndTime", false, updatePolicy.installTime.installWindowEnd)) {
        EDMLOGE("SetOTAUpdatePolicy JsObjToUpdateTime installEndTime trans failed!");
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
    std::string version;
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
    return true;
}

bool SystemManagerAddon::ParsePackages(napi_env env, napi_value object, std::vector<Package> &packages)
{
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
    return JsObjectToString(env, object, "path", true, package.path);
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