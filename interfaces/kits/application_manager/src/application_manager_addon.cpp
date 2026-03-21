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

#include "clear_up_application_data_param.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "kiosk_feature.h"
#include "napi_edm_adapter.h"
#include "edm_errors.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_manager.h"
#endif

#ifdef FEATURE_PC_ONLY
#include "dock_info.h"
#endif

using namespace OHOS::EDM;

const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
napi_value ApplicationManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value nKioskFeature = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nKioskFeature));
    CreateKioskFeatureObject(env, nKioskFeature);

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
        DECLARE_NAPI_FUNCTION("addAllowedRunningBundles", AddAllowedRunningBundles),
        DECLARE_NAPI_FUNCTION("removeAllowedRunningBundles", RemoveAllowedRunningBundles),
        DECLARE_NAPI_FUNCTION("getAllowedRunningBundles", GetAllowedRunningBundles),
        DECLARE_NAPI_FUNCTION("setKioskFeatures", SetKioskFeatures),
        DECLARE_NAPI_FUNCTION("addKeepAliveApps", AddKeepAliveApps),
        DECLARE_NAPI_FUNCTION("removeKeepAliveApps", RemoveKeepAliveApps),
        DECLARE_NAPI_FUNCTION("getKeepAliveApps", GetKeepAliveApps),
        DECLARE_NAPI_FUNCTION("setAllowedKioskApps", SetAllowedKioskApps),
        DECLARE_NAPI_FUNCTION("getAllowedKioskApps", GetAllowedKioskApps),
        DECLARE_NAPI_FUNCTION("isAppKioskAllowed", IsAppKioskAllowed),
        DECLARE_NAPI_PROPERTY("KioskFeature", nKioskFeature),
        DECLARE_NAPI_FUNCTION("clearUpApplicationData", ClearUpApplicationData),
        DECLARE_NAPI_FUNCTION("isModifyKeepAliveAppsDisallowed", IsModifyKeepAliveAppsDisallowed),
        DECLARE_NAPI_FUNCTION("isModifyAutoStartAppsDisallowed", IsModifyAutoStartAppsDisallowed),
        DECLARE_NAPI_FUNCTION("addFreezeExemptedApps", AddFreezeExemptedApps),
        DECLARE_NAPI_FUNCTION("removeFreezeExemptedApps", RemoveFreezeExemptedApps),
        DECLARE_NAPI_FUNCTION("getFreezeExemptedApps", GetFreezeExemptedApps),
        DECLARE_NAPI_FUNCTION("addUserNonStopApps", AddUserNonStopApps),
        DECLARE_NAPI_FUNCTION("removeUserNonStopApps", RemoveUserNonStopApps),
        DECLARE_NAPI_FUNCTION("getUserNonStopApps", GetUserNonStopApps),
        DECLARE_NAPI_FUNCTION("setAbilityDisabled", SetAbilityDisabled),
        DECLARE_NAPI_FUNCTION("isAbilityDisabled", IsAbilityDisabled),
        DECLARE_NAPI_FUNCTION("addDockApp", AddDockApp),
        DECLARE_NAPI_FUNCTION("removeDockApp", RemoveDockApp),
        DECLARE_NAPI_FUNCTION("getDockApps", GetDockApps),
        DECLARE_NAPI_FUNCTION("addAllowedNotificationBundles", AddAllowedNotificationBundles),
        DECLARE_NAPI_FUNCTION("removeAllowedNotificationBundles", RemoveAllowedNotificationBundles),
        DECLARE_NAPI_FUNCTION("getAllowedNotificationBundles", GetAllowedNotificationBundles),
        DECLARE_NAPI_FUNCTION("queryTrafficStats", QueryTrafficStats),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value ApplicationManagerAddon::IsModifyKeepAliveAppsDisallowed(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsModifyKeepAliveAppsDisallowed called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter elementName error");
    
    int32_t userId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, userId, argv[ARR_INDEX_ONE]), "Parameter userId error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    
    std::string keepAliveApp;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, keepAliveApp, argv[ARR_INDEX_TWO]) && keepAliveApp.size() > 0,
        "Parameter keepAliveApps error");

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    bool isModifyKeepAliveAppsDisallowed = true;
    int32_t ret = applicationManagerProxy->IsModifyKeepAliveAppsDisallowed(elementName, keepAliveApp,
        userId, isModifyKeepAliveAppsDisallowed);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiIsModify = nullptr;
    napi_get_boolean(env, isModifyKeepAliveAppsDisallowed, &napiIsModify);
    return napiIsModify;
}

napi_value ApplicationManagerAddon::AddAllowedNotificationBundles(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddAllowedNotificationBundles called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "AddAllowedNotificationBundles";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::ARRAY_STRING,
        EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.argsConvert = {nullptr, nullptr, nullptr};
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = applicationManagerProxy->AddAllowedNotificationBundles(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("AddAllowedNotificationBundles failed!");
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::RemoveAllowedNotificationBundles(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveAllowedNotificationBundles called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "RemoveAllowedNotificationBundles";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::ARRAY_STRING,
        EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.argsConvert = {nullptr, nullptr, nullptr};
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = applicationManagerProxy->RemoveAllowedNotificationBundles(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("RemoveAllowedNotificationBundles failed!");
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::GetAllowedNotificationBundles(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAllowedNotificationBundles called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetAllowedNotificationBundles";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL, EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.argsConvert = {nullptr, nullptr};
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    std::vector<std::string> bundleNames;
    int32_t ret = applicationManagerProxy->GetAllowedNotificationBundles(adapterAddonData.data, bundleNames);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("GetAllowedNotificationBundles failed!");
        return nullptr;
    }
    napi_value bundleArray;
    NAPI_CALL(env, napi_create_array(env, &bundleArray));
    for (size_t i = 0; i < bundleNames.size(); ++i) {
        napi_value bundleName;
        NAPI_CALL(env, napi_create_string_utf8(env, bundleNames[i].c_str(), NAPI_AUTO_LENGTH, &bundleName));
        NAPI_CALL(env, napi_set_element(env, bundleArray, i, bundleName));
    }
    return bundleArray;
}

napi_value ApplicationManagerAddon::AddKeepAliveApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddKeepAliveApps called");
    return AddOrRemoveKeepAliveApps(env, info, "AddKeepAliveApps");
}

napi_value ApplicationManagerAddon::RemoveKeepAliveApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveKeepAliveApps called");
    return AddOrRemoveKeepAliveApps(env, info, "RemoveKeepAliveApps");
}

napi_value ApplicationManagerAddon::AddOrRemoveKeepAliveApps(napi_env env, napi_callback_info info,
    std::string function)
{
    EDMLOGI("NAPI_AddOrRemoveKeepAliveApps called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter elementName error");
    std::vector<std::string> keepAliveApps;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, keepAliveApps, argv[ARR_INDEX_ONE]),
        "Parameter keepAliveApps error");
    int32_t userId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, userId, argv[ARR_INDEX_TWO]), "Parameter userId error");
    bool disallowModify = true;
    if (argc >= ARGS_SIZE_FOUR) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallowModify, argv[ARR_INDEX_THREE]),
            "Parameter disallowModify error");
        EDMLOGI("NAPI_AddOrRemoveKeepAliveApps called disallowModify: %{public}d", disallowModify);
    }
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = 0;
    std::string retMessage;
    if (function == "AddKeepAliveApps") {
        ret = applicationManagerProxy->AddKeepAliveApps(elementName, keepAliveApps, disallowModify, userId, retMessage);
    } else {
        ret = applicationManagerProxy->RemoveKeepAliveApps(elementName, keepAliveApps, userId);
    }
    if (FAILED(ret)) {
        if (ret == EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED) {
            napi_throw(env, CreateErrorWithInnerCode(env, ret, retMessage));
        } else {
            napi_throw(env, CreateError(env, ret));
        }
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::GetKeepAliveApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetKeepAliveApps called");
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
    int32_t userId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, userId, argv[ARR_INDEX_ONE]), "Parameter userId error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    std::vector<std::string> keepAliveApps;
    int32_t ret = applicationManagerProxy->GetKeepAliveApps(elementName, keepAliveApps, userId);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiKeepAliveApps = nullptr;
    napi_create_array(env, &napiKeepAliveApps);
    ConvertStringVectorToJS(env, keepAliveApps, napiKeepAliveApps);
    return napiKeepAliveApps;
}

napi_value ApplicationManagerAddon::AddFreezeExemptedApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddFreezeExemptedApps called");
    return AddOrRemoveFreezeExemptedApps(env, info, "AddFreezeExemptedApps");
}

napi_value ApplicationManagerAddon::RemoveFreezeExemptedApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveFreezeExemptedApps called");
    return AddOrRemoveFreezeExemptedApps(env, info, "RemoveFreezeExemptedApps");
}

napi_value ApplicationManagerAddon::AddOrRemoveFreezeExemptedApps(napi_env env, napi_callback_info info,
    std::string function)
{
    EDMLOGI("NAPI_AddOrRemoveFreezeExemptedApps called");
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
    std::vector<ApplicationInstance> freezeExemptedApps;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseApplicationInstanceArray(env, freezeExemptedApps, argv[ARR_INDEX_ONE]),
        "Parameter freezeExemptedApps error");
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = 0;
    if (function == "AddFreezeExemptedApps") {
        ret = applicationManagerProxy->AddFreezeExemptedApps(elementName, freezeExemptedApps);
    } else {
        ret = applicationManagerProxy->RemoveFreezeExemptedApps(elementName, freezeExemptedApps);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::GetFreezeExemptedApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetFreezeExemptedApps called");
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

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    std::vector<ApplicationInstance> freezeExemptedApps;
    int32_t ret = applicationManagerProxy->GetFreezeExemptedApps(elementName, freezeExemptedApps);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiFreezeExemptedApps = nullptr;
    napi_create_array(env, &napiFreezeExemptedApps);
    ConvertApplicationInstanceVectorToJS(env, freezeExemptedApps, napiFreezeExemptedApps);
    return napiFreezeExemptedApps;
}

napi_value ApplicationManagerAddon::AddUserNonStopApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddUserNonStopApps called");
    return AddOrRemoveUserNonStopApps(env, info, "AddUserNonStopApps");
}

napi_value ApplicationManagerAddon::RemoveUserNonStopApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveUserNonStopApps called");
    return AddOrRemoveUserNonStopApps(env, info, "RemoveUserNonStopApps");
}

napi_value ApplicationManagerAddon::AddOrRemoveUserNonStopApps(napi_env env, napi_callback_info info,
    std::string function)
{
    EDMLOGI("NAPI_AddOrRemoveUserNonStopApps called");
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
    std::vector<ApplicationInstance> userNonStopApps;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseApplicationInstanceArray(env, userNonStopApps, argv[ARR_INDEX_ONE]),
        "Parameter userNonStopApps error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = 0;
    if (function == "AddUserNonStopApps") {
        ret = applicationManagerProxy->AddUserNonStopApps(elementName, userNonStopApps);
    } else {
        ret = applicationManagerProxy->RemoveUserNonStopApps(elementName, userNonStopApps);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::GetUserNonStopApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetUserNonStopApps called");
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

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    std::vector<ApplicationInstance> userNonStopApps;
    int32_t ret = applicationManagerProxy->GetUserNonStopApps(elementName, userNonStopApps);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiUserNonStopApps = nullptr;
    napi_create_array(env, &napiUserNonStopApps);
    ConvertApplicationInstanceVectorToJS(env, userNonStopApps, napiUserNonStopApps);
    return napiUserNonStopApps;
}

void ApplicationManagerAddon::JoinParcelData(MessageParcel &parcelData, int32_t userId,
    OHOS::AppExecFwk::ElementName &elementName, std::vector<OHOS::EDM::EdmElementName> autoStartApps)
{
    parcelData.WriteInterfaceToken(DESCRIPTOR);
    parcelData.WriteInt32(HAS_USERID);
    parcelData.WriteInt32(userId);
    parcelData.WriteParcelable(&elementName);
    parcelData.WriteString(WITHOUT_PERMISSION_TAG);
    std::vector<std::string> autoStartAppsString;
    for (size_t i = 0; i < autoStartApps.size(); i++) {
        std::string isHiddenStartString = autoStartApps[i].GetIsHiddenStart() ? "true" : "false";
        std::string appWant = autoStartApps[i].GetBundleName() + "/" + autoStartApps[i].GetAbilityName() +
 	        "/" + isHiddenStartString;
        autoStartAppsString.push_back(appWant);
    }
    parcelData.WriteStringVector(autoStartAppsString);
}

napi_value ApplicationManagerAddon::AddAutoStartApps(napi_env env, napi_callback_info info)
{
    return AddOrRemoveAutoStartApps(env, info, "AddAutoStartApps");
}

napi_value ApplicationManagerAddon::RemoveAutoStartApps(napi_env env, napi_callback_info info)
{
    return AddOrRemoveAutoStartApps(env, info, "RemoveAutoStartApps");
}

bool ApplicationManagerAddon::EdmParseElementName(napi_env env, OHOS::EDM::EdmElementName &elementName, napi_value args)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        EDMLOGE("Parameter element valueType error");
        return false;
    }
    std::string bundleName;
    std::string abilityName;
    bool isHiddenStart = false;
    bool hasParameters;
    if (!JsObjectToString(env, args, "bundleName", true, bundleName) ||
        !JsObjectToString(env, args, "abilityName", true, abilityName)) {
        EDMLOGE("Parameter element bundleName error");
        return false;
    }
    EDMLOGD("EdmParseElementName bundleName %{public}s ", bundleName.c_str());
    EDMLOGD("EdmParseElementName abilityname %{public}s", abilityName.c_str());

    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    
    napi_has_named_property(env, args, "parameters", &hasParameters);
    if (hasParameters) {
        napi_value parameters;
        napi_get_named_property(env, args, "parameters", &parameters);
        JsObjectToBool(env, parameters, "isHiddenStart", false, isHiddenStart);
    }
    elementName.SetIsHiddenStart(isHiddenStart);
    EDMLOGD("GetAutoStartApps parse auto start app set parameters isHiddenStart OK");
    
    return true;
}

napi_value ApplicationManagerAddon::EdmParseElementArray(napi_env env,
    std::vector<OHOS::EDM::EdmElementName> &elementArray, napi_value args)
{
    EDMLOGD("begin to parse element array");
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, args, &isArray));
    if (!isArray) {
        EDMLOGE("napi object is not array.");
        return nullptr;
    }
    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, args, &arrayLength));
    EDMLOGD("length=%{public}ud", arrayLength);
    for (uint32_t j = 0; j < arrayLength; j++) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_get_element(env, args, j, &value));
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, value, &valueType));
        if (valueType != napi_object) {
            elementArray.clear();
            return nullptr;
        }
        OHOS::EDM::EdmElementName element;
        EdmParseElementName(env, element, value);
        elementArray.push_back(element);
    }
    // create result code
    napi_value result;
    napi_status status = napi_create_int32(env, NAPI_RETURN_ONE, &result);
    if (status != napi_ok) {
        return nullptr;
    }
    return result;
}
 	 
napi_value ApplicationManagerAddon::AddOrRemoveAutoStartApps(napi_env env, napi_callback_info info,
    std::string function)
{
    EDMLOGI("NAPI_AddOrRemoveAutoStartApps called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter elementName error");
    std::vector<OHOS::EDM::EdmElementName> autoStartApps;
    ASSERT_AND_THROW_PARAM_ERROR(env, EdmParseElementArray(env, autoStartApps, argv[ARR_INDEX_ONE]),
        "Parameter autoStartApps error");
    int32_t userId = 0;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    if ((argc >= ARGS_SIZE_FOUR && function == "AddAutoStartApps") ||
        (argc >= ARGS_SIZE_THREE && function == "removeAutoStartApps")) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, userId, argv[ARR_INDEX_TWO]), "Parameter userId error");
    }
    MessageParcel parcelData;
    JoinParcelData(parcelData, userId, elementName, autoStartApps);
    bool disallowModify = true;
    if (argc >= ARGS_SIZE_FOUR) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallowModify, argv[ARR_INDEX_THREE]),
            "Parameter disallowModify error");
        EDMLOGI("NAPI_AddOrRemoveAutoStartApps called disallowModify: %{public}d", disallowModify);
    }
    parcelData.WriteBool(disallowModify);
    std::string retMessage;
    int32_t ret = ApplicationManagerProxy::GetApplicationManagerProxy()->AddOrRemoveAutoStartApps(
        parcelData, function == "AddAutoStartApps", retMessage);
    if (FAILED(ret)) {
        if (ret == EDM_ADD_AUTO_START_APP_FAILED) {
            napi_throw(env, CreateError(env, EdmReturnErrCode::PARAM_ERROR, retMessage));
        } else {
            napi_throw(env, CreateError(env, ret));
        }
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::ParseAutoStartAppsInfo(napi_env env, napi_value &napiAutoStartApps,
    std::vector<EdmElementName> autoStartApps)
{
    size_t idx = 0;
    for (const auto &element : autoStartApps) {
        napi_value objAutoStartApps = nullptr;
        NAPI_CALL(env, napi_create_object(env, &objAutoStartApps));
        napi_value napi_bundleName;
        napi_value napi_abilityName;
        napi_value napi_isHiddenStart;
        NAPI_CALL(env, napi_create_string_utf8(env, element.GetBundleName().c_str(),
            element.GetBundleName().size(), &napi_bundleName));
        NAPI_CALL(env, napi_create_string_utf8(env, element.GetAbilityName().c_str(),
            element.GetAbilityName().size(), &napi_abilityName));
        NAPI_CALL(env, napi_get_boolean(env, element.GetIsHiddenStart(), &napi_isHiddenStart));
        NAPI_CALL(env, napi_set_named_property(env, objAutoStartApps, "bundleName", napi_bundleName));
        NAPI_CALL(env, napi_set_named_property(env, objAutoStartApps, "abilityName", napi_abilityName));
        napi_value objParamenters = nullptr;
        NAPI_CALL(env, napi_create_object(env, &objParamenters));
        NAPI_CALL(env, napi_set_named_property(env, objParamenters, "isHiddenStart", napi_isHiddenStart));
        NAPI_CALL(env, napi_set_named_property(env, objAutoStartApps, "parameters", objParamenters));
        napi_set_element(env, napiAutoStartApps, idx, objAutoStartApps);
        idx++;
    }
    return napiAutoStartApps;
}

napi_value ApplicationManagerAddon::GetAutoStartApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAutoStartApps called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter elementName error");
    int32_t userId = 0;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    if (argc >= ARGS_SIZE_TWO) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, userId, argv[ARR_INDEX_ONE]), "Parameter userId error");
    }
    MessageParcel parcelData;
    SetBaseDataForGetPolicy(userId, parcelData);
    parcelData.WriteInt32(HAS_ADMIN);
    parcelData.WriteParcelable(&elementName);
    parcelData.WriteString(OHOS::EDM::EdmConstants::AutoStart::GET_MANAGE_AUTO_START_APPS_BUNDLE_INFO);
    std::vector<OHOS::EDM::EdmElementName> autoStartApps;
    int32_t ret = ApplicationManagerProxy::GetApplicationManagerProxy()->GetAutoStartApps(
        parcelData, autoStartApps);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiAutoStartApps = nullptr;
    NAPI_CALL(env, napi_create_array(env, &napiAutoStartApps));
    ParseAutoStartAppsInfo(env, napiAutoStartApps, autoStartApps);
    return napiAutoStartApps;
}

void ApplicationManagerAddon::SetBaseDataForGetPolicy(int32_t userId, MessageParcel &data)
{
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteString(WITHOUT_PERMISSION_TAG);
}

napi_value ApplicationManagerAddon::IsModifyAutoStartAppsDisallowed(napi_env env, napi_callback_info info)
{
    EDMLOGI("IsModifyAutoStartAppsDisallowed called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter elementName error");
    OHOS::AppExecFwk::ElementName autoStartApp;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, autoStartApp, argv[ARR_INDEX_ONE]),
        "Parameter autoStartApp error");
    int32_t userId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, userId, argv[ARR_INDEX_TWO]), "Parameter userId error");
    MessageParcel parcelData;
    parcelData.WriteInterfaceToken(DESCRIPTOR);
    parcelData.WriteInt32(HAS_USERID);
    parcelData.WriteInt32(userId);
    parcelData.WriteString(WITHOUT_PERMISSION_TAG);
    parcelData.WriteInt32(HAS_ADMIN);
    parcelData.WriteParcelable(&elementName);
    parcelData.WriteString(OHOS::EDM::EdmConstants::AutoStart::GET_MANAGE_AUTO_START_APP_DISALLOW_MODIFY);
    std::string appWant = autoStartApp.GetBundleName() + "/" + autoStartApp.GetAbilityName();
    parcelData.WriteString(appWant);

    bool isModifyAutoStartAppDisallowed = true;
    int32_t ret = ApplicationManagerProxy::GetApplicationManagerProxy()->IsModifyAutoStartAppsDisallowed(
        parcelData, isModifyAutoStartAppDisallowed);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiIsModify = nullptr;
    napi_get_boolean(env, isModifyAutoStartAppDisallowed, &napiIsModify);
    return napiIsModify;
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
    return AddOrRemoveDisallowedRunningBundles(env, info, "AddDisallowedRunningBundles",
        NativeAddDisallowedRunningBundles);
}

napi_value ApplicationManagerAddon::RemoveDisallowedRunningBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemoveDisallowedRunningBundles(env, info, "RemoveDisallowedRunningBundles",
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

napi_value ApplicationManagerAddon::AddOrRemoveDisallowedRunningBundles(napi_env env, napi_callback_info info,
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
    NAPI_CALL(env, napi_create_array(env, &result));
    ConvertStringVectorToJS(env, appIds, result);
    return result;
}

napi_value ApplicationManagerAddon::AddAllowedRunningBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemoveAllowedRunningBundles(env, info, true);
}

napi_value ApplicationManagerAddon::RemoveAllowedRunningBundles(napi_env env, napi_callback_info info)
{
    return AddOrRemoveAllowedRunningBundles(env, info, false);
}

napi_value ApplicationManagerAddon::AddOrRemoveAllowedRunningBundles(napi_env env, napi_callback_info info,
    bool isAdd)
{
    EDMLOGI("NAPI_AddOrRemoveAllowedRunningBundles called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_object),
        "parameter appIdentifies error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_number),
        "parameter accountId error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    std::vector<std::string> appIdentifies;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, appIdentifies, argv[ARR_INDEX_ONE]),
        "parameter appIdentifies parse error");
    EDMLOGD("AddOrRemoveAllowedRunningBundles: "
        "elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    int32_t accountId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_TWO]),
        "parameter accountId parse error");
 
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    if (applicationManagerProxy == nullptr) {
        EDMLOGE("can not get applicationManagerProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    int32_t ret = applicationManagerProxy->DealAllowedRunningBundles(elementName, appIdentifies, accountId, isAdd);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::GetAllowedRunningBundles(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAllowedRunningBundles called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    EDMLOGD("GetAllowedRunningBundles: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    int32_t accountId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_number),
        "parameter accountId error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_ONE]),
        "parameter accountId parse error");

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    if (applicationManagerProxy == nullptr) {
        EDMLOGE("can not get applicationManagerProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    std::vector<std::string> appIdentifies;
    int32_t ret = applicationManagerProxy->GetAllowedRunningBundles(elementName, accountId, appIdentifies);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_array(env, &result));
    ConvertStringVectorToJS(env, appIdentifies, result);
    return result;
}

void ApplicationManagerAddon::CreateKioskFeatureObject(napi_env env, napi_value value)
{
    napi_value nAllowNotificationCenter;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(KioskFeature::ALLOW_NOTIFICATION_CENTER), &nAllowNotificationCenter));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ALLOW_NOTIFICATION_CENTER",
        nAllowNotificationCenter));

    napi_value nAllowContorlCenter;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(KioskFeature::ALLOW_CONTROL_CENTER), &nAllowContorlCenter));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ALLOW_CONTROL_CENTER", nAllowContorlCenter));

    napi_value nAllowGestureControl;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(KioskFeature::ALLOW_GESTURE_CONTROL), &nAllowGestureControl));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ALLOW_GESTURE_CONTROL", nAllowGestureControl));

    napi_value nAllowSideDock;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(KioskFeature::ALLOW_SIDE_DOCK), &nAllowSideDock));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "ALLOW_SIDE_DOCK", nAllowSideDock));
}

napi_value ApplicationManagerAddon::SetKioskFeatures(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetKioskFeatures called");
    auto convertKioskFeature2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
        std::vector<int32_t> kioskFeatures;
        bool parseRet = ParseIntArray(env, kioskFeatures, argv);
        if (!parseRet) {
            EDMLOGE("NAPI_SetKioskFeatures ParseIntArray fail");
            return false;
        }
        data.WriteInt32Vector(kioskFeatures);
        return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetKioskFeatures";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.argsConvert = {nullptr, convertKioskFeature2Data};
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = applicationManagerProxy->SetKioskFeatures(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SetKioskFeatures failed!");
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::SetAllowedKioskApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetAllowedKioskApps called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(
        env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "The first parameter must be want.");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(
        env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]), "Parameter elementName error");
    std::vector<std::string> appIdentifiers;
    ASSERT_AND_THROW_PARAM_ERROR(
        env, ParseStringArray(env, appIdentifiers, argv[ARR_INDEX_ONE]), "Parameter appIdentifiers error");
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = applicationManagerProxy->SetAllowedKioskApps(elementName, appIdentifiers);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::GetAllowedKioskApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAllowedKioskApps called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(
        env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "The first parameter must be want.");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(
        env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]), "Parameter elementName error");
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    std::vector<std::string> appIdentifiers;
    int32_t ret = applicationManagerProxy->GetAllowedKioskApps(elementName, appIdentifiers);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiAppIdentifiers = nullptr;
    NAPI_CALL(env, napi_create_array(env, &napiAppIdentifiers));
    ConvertStringVectorToJS(env, appIdentifiers, napiAppIdentifiers);
    return napiAppIdentifiers;
}

napi_value ApplicationManagerAddon::IsAppKioskAllowed(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsAppKioskAllowed called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(
        env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_string), "Parameter appIdentifier error.");
    std::string appIdentifier;
    ASSERT_AND_THROW_PARAM_ERROR(
        env, ParseString(env, appIdentifier, argv[ARR_INDEX_ZERO]), "Parameter appIdentifier parse error");
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    bool isAllowed = false;
    int32_t ret = applicationManagerProxy->IsAppKioskAllowed(appIdentifier, isAllowed);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isAllowed, &result));
    return result;
}

napi_value ApplicationManagerAddon::ClearUpApplicationData(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_ClearUpApplicationData called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = { nullptr };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_FOUR, "Parameter count error.");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "Parameter admin error.");
    ASSERT_AND_THROW_PARAM_ERROR(
        env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "Parameter bundleName error.");
    ASSERT_AND_THROW_PARAM_ERROR(
        env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_number), "Parameter appIndex error.");
    ASSERT_AND_THROW_PARAM_ERROR(
        env, MatchValueType(env, argv[ARR_INDEX_THREE], napi_number), "Parameter accountId error.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(
        env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]), "Parameter elementName parse error.");

    ClearUpApplicationDataParam param;
    ASSERT_AND_THROW_PARAM_ERROR(
        env, ParseString(env, param.bundleName, argv[ARR_INDEX_ONE]), "Parameter bundleName parse error.");
    ASSERT_AND_THROW_PARAM_ERROR(
        env, ParseInt(env, param.appIndex, argv[ARR_INDEX_TWO]), "Parameter appIndex parse error.");
    ASSERT_AND_THROW_PARAM_ERROR(
        env, ParseInt(env, param.userId, argv[ARR_INDEX_THREE]), "Parameter accountId parse error.");
    EDMLOGD("EnableAdmin: elementName.bundlename %{public}s, "
            "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = applicationManagerProxy->ClearUpApplicationData(elementName, param);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }

    return nullptr;
}

napi_value ApplicationManagerAddon::SetAbilityDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetAbilityDisabled called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetAbilityDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::STRING, EdmAddonCommonType::USERID,
        EdmAddonCommonType::STRING, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.argsConvert = {nullptr, nullptr, nullptr, nullptr, nullptr};
    addonMethodSign.apiVersionTag = EdmConstants::PERMISSION_TAG_VERSION_23;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = applicationManagerProxy->SetAbilityDisabled(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value ApplicationManagerAddon::IsAbilityDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsAbilityDisabled called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "IsAbilityDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::STRING, EdmAddonCommonType::USERID,
        EdmAddonCommonType::STRING};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.argsConvert = {nullptr, nullptr, nullptr, nullptr};
    addonMethodSign.apiVersionTag = EdmConstants::PERMISSION_TAG_VERSION_23;
    AdapterAddonData adapterAddonData{};
    napi_value res = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (res == nullptr) {
        return nullptr;
    }

    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    bool isDisabled = false;
    int32_t ret = applicationManagerProxy->IsAbilityDisabled(adapterAddonData.data, isDisabled);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isDisabled, &result));
    return result;
}

napi_value ApplicationManagerAddon::AddDockApp(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddDockApp called");
    return AddOrRemoveDockApp(env, info, "AddDockApp");
}

napi_value ApplicationManagerAddon::RemoveDockApp(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveDockApp called");
    return AddOrRemoveDockApp(env, info, "RemoveDockApp");
}

napi_value ApplicationManagerAddon::AddOrRemoveDockApp(napi_env env, napi_callback_info info,
    std::string function)
{
    EDMLOGI("NAPI_AddOrRemoveDockApp called");
#ifdef FEATURE_PC_ONLY
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter elementName error");
    std::string bundleName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, bundleName, argv[ARR_INDEX_ONE]),
        "Parameter bundleName error");
    std::string abilityName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, abilityName, argv[ARR_INDEX_TWO]),
        "Parameter abilityName error");

    EDMLOGD("EnableAdmin: elementName.bundlename %{public}s, elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = 0;
    if (function == "AddDockApp") {
        bool hasIndex = false;
        int32_t index = -1;
        if (argc >= ARGS_SIZE_FOUR) {
            ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, index, argv[ARR_INDEX_THREE]), "Parameter index error");
            hasIndex = true;
        }
        ret = applicationManagerProxy->AddDockApp(elementName, bundleName, abilityName, hasIndex, index);
    } else {
        ret = applicationManagerProxy->RemoveDockApp(elementName, bundleName, abilityName);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("ApplicationManagerAddon::AddOrRemoveDockApp Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value ApplicationManagerAddon::GetDockApps(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDockApps called");
#ifdef FEATURE_PC_ONLY
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

    EDMLOGD("EnableAdmin: elementName.bundlename %{public}s, elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    auto applicationManagerProxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    int32_t ret = 0;
    std::vector<DockInfo> dockInfos;
    ret = applicationManagerProxy->GetDockApps(elementName, dockInfos);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value nDockInfos;
    NAPI_CALL(env, napi_create_array(env, &nDockInfos));
    ConvertDockInfoVectorToJs(env, dockInfos, nDockInfos);
    return nDockInfos;
#else
    EDMLOGW("ApplicationManagerAddon::AddOrRemoveDockApp Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

#ifdef FEATURE_PC_ONLY
void ApplicationManagerAddon::ConvertDockInfoVectorToJs(napi_env env, const std::vector<DockInfo> &dockInfos,
    napi_value &nDockInfos)
{
    EDMLOGD("ConvertDockInfoVectorToJs size: %{public}zu", dockInfos.size());
    size_t idx = 0;
    for (const auto &dockInfo : dockInfos) {
        napi_value obj = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &obj));
        napi_value bundleName;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, dockInfo.bundleName.c_str(),
            NAPI_AUTO_LENGTH, &bundleName));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "bundleName", bundleName));
        napi_value abilityName;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, dockInfo.abilityName.c_str(),
            NAPI_AUTO_LENGTH, &abilityName));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "abilityName", abilityName));
        napi_value index;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, dockInfo.index, &index));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "index", index));
        napi_set_element(env, nDockInfos, idx, obj);
        idx++;
    }
}
#endif

napi_value ApplicationManagerAddon::QueryTrafficStats(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_QueryTrafficStats called");
#ifdef NETMANAGER_BASE_EDM_ENABLE
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_FIVE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object),
        "parameter admin error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncQueryTrafficStatsCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncQueryTrafficStatsCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName,
        argv[ARR_INDEX_ZERO]), "element name param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->networkInfo.bundleName,
        argv[ARR_INDEX_ONE]), "bundleName param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->networkInfo.appIndex,
        argv[ARR_INDEX_TWO]), "appIndex param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->networkInfo.accountId,
        argv[ARR_INDEX_THREE]), "accountId param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseNetworkInfo(env, asyncCallbackInfo->networkInfo,
        argv[ARR_INDEX_FOUR]), "networkInfo param error");

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "QueryTrafficStats",
        NativeQueryTrafficStats, NativeQueryTrafficStatsComplete);
    callbackPtr.release();
    return asyncWorkReturn;
#else
    EDMLOGW("ApplicationManagerAddon::QueryTrafficStats Unsupported Capabilities.");
    napi_value result = nullptr;
    napi_deferred deferred = nullptr;
    auto status = napi_create_promise(env, &deferred, &result);
    if (status == napi_ok) {
        napi_reject_deferred(env, deferred, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    }
    return result;
#endif
}

bool ApplicationManagerAddon::ParseNetworkInfo(napi_env env, NetStatsNetwork &networkInfo, napi_value args)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        EDMLOGE("Parameter networkInfo valueType error");
        return false;
    }
    uint32_t type = 0;
    int64_t startTime = 0;
    int64_t endTime = 0;
    uint32_t simId = UINT32_MAX;
    if (!JsObjectToUint(env, args, "type", true, type) ||
        !JsObjectToLong(env, args, "startTime", true, startTime) ||
        !JsObjectToLong(env, args, "endTime", true, endTime) ||
        !JsObjectToUint(env, args, "simId", false, simId)) {
        EDMLOGE("Parameter networkInfo error");
        return false;
    }
    networkInfo.type = type;
    networkInfo.startTime = startTime;
    networkInfo.endTime = endTime;
    networkInfo.simId = simId;
    return true;
}

void ApplicationManagerAddon::NativeQueryTrafficStats(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeQueryTrafficStats called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncQueryTrafficStatsCallbackInfo *>(data);
    auto proxy = ApplicationManagerProxy::GetApplicationManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get ApplicationManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = proxy->QueryTrafficStats(asyncCallbackInfo->elementName,
        asyncCallbackInfo->networkInfo, asyncCallbackInfo->netStatsInfo);
}

void ApplicationManagerAddon::NativeQueryTrafficStatsComplete(napi_env env, napi_status status,
    void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncQueryTrafficStatsCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        if (asyncCallbackInfo->ret == ERR_OK) {
            NetStatsInfo netStatsInfo = asyncCallbackInfo->netStatsInfo;
            napi_value result = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result));
            napi_value rxBytes = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, netStatsInfo.rxBytes, &rxBytes));
            NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "rxBytes", rxBytes));
            napi_value txBytes = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, netStatsInfo.txBytes, &txBytes));
            NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "txBytes", txBytes));
            napi_value rxPackets = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, netStatsInfo.rxPackets, &rxPackets));
            NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "rxPackets", rxPackets));
            napi_value txPackets = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, netStatsInfo.txPackets, &txPackets));
            NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "txPackets", txPackets));
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, result);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
        }
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
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