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

#include "restrictions_addon.h"

#include <algorithm>
#include <vector>

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "hisysevent_adapter.h"

using namespace OHOS::EDM;

std::unordered_map<std::string, uint32_t> RestrictionsAddon::labelCodeMap = {
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_BLUETOOTH, EdmInterfaceCode::DISABLE_BLUETOOTH},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MODIFY_DATETIME, EdmInterfaceCode::DISALLOW_MODIFY_DATETIME},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_PRINTER, EdmInterfaceCode::DISABLED_PRINTER},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_HDC, EdmInterfaceCode::DISABLED_HDC},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MIC, EdmInterfaceCode::DISABLE_MICROPHONE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_FINGER_PRINT, EdmInterfaceCode::FINGERPRINT_AUTH},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_USB, EdmInterfaceCode::DISABLE_USB},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_WIFI, EdmInterfaceCode::DISABLE_WIFI},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MTP_CLIENT, EdmInterfaceCode::DISABLE_MTP_CLIENT},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MTP_SERVER, EdmInterfaceCode::DISABLE_MTP_SERVER},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SAMBA_CLIENT, EdmInterfaceCode::DISABLE_SAMBA_CLIENT},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SAMBA_SERVER, EdmInterfaceCode::DISABLE_SAMBA_SERVER},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MAINTENANCE_MODE, EdmInterfaceCode::DISABLE_MAINTENANCE_MODE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_REMOTE_DESK, EdmInterfaceCode::DISABLE_REMOTE_DESK},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_REMOTE_DIAGNOSIS, EdmInterfaceCode::DISABLE_REMOTE_DIAGNOSIS},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SCREENSHOT, EdmInterfaceCode::POLICY_CODE_END + 11},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SCREEN_RECORD, EdmInterfaceCode::POLICY_CODE_END + 12},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_DISK_RECOVERY_KEY, EdmInterfaceCode::POLICY_CODE_END + 17},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_NEAR_LINK, EdmInterfaceCode::POLICY_CODE_END + 18},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_TETHERING, EdmInterfaceCode::DISALLOWED_TETHERING},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_INACTIVE_USER_FREEZE, EdmInterfaceCode::INACTIVE_USER_FREEZE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_CAMERA, EdmInterfaceCode::DISABLE_CAMERA},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_DEVELOPER_MODE, POLICY_CODE_END + 20},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_RESET_FACTORY, POLICY_CODE_END + 21},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SMS, EdmInterfaceCode::DISALLOWED_SMS},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MMS, EdmInterfaceCode::DISALLOWED_MMS},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_BACKUP_AND_RESTORE,
        EdmInterfaceCode::DISABLE_BACKUP_AND_RESTORE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MOBILE_DATA, EdmInterfaceCode::DISALLOWED_MOBILE_DATA},
};

std::unordered_map<std::string, uint32_t> RestrictionsAddon::itemCodeMap = {
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_APN, EdmInterfaceCode::DISALLOW_MODIFY_APN},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_POWER_LONG_PRESS, EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS}
};

std::vector<uint32_t> RestrictionsAddon::multiPermCodes = {
    EdmInterfaceCode::DISABLE_BLUETOOTH,
    EdmInterfaceCode::DISALLOW_MODIFY_DATETIME,
    EdmInterfaceCode::DISABLED_PRINTER,
    EdmInterfaceCode::DISABLED_HDC,
    EdmInterfaceCode::DISABLE_USB,
    EdmInterfaceCode::DISABLE_WIFI,
};

std::unordered_map<std::string, uint32_t> RestrictionsAddon::labelCodeMapForAccount = {
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_FINGER_PRINT, EdmInterfaceCode::FINGERPRINT_AUTH},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MTP_CLIENT, EdmInterfaceCode::DISABLE_USER_MTP_CLIENT},
};

napi_value RestrictionsAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setPrinterDisabled", SetPrinterDisabled),
        DECLARE_NAPI_FUNCTION("isPrinterDisabled", IsPrinterDisabled),
        DECLARE_NAPI_FUNCTION("setHdcDisabled", SetHdcDisabled),
        DECLARE_NAPI_FUNCTION("isHdcDisabled", IsHdcDisabled),
        DECLARE_NAPI_FUNCTION("disableMicrophone", DisableMicrophone),
        DECLARE_NAPI_FUNCTION("isMicrophoneDisabled", IsMicrophoneDisabled),
        DECLARE_NAPI_FUNCTION("setFingerprintAuthDisabled", SetFingerprintAuthDisabled),
        DECLARE_NAPI_FUNCTION("isFingerprintAuthDisabled", IsFingerprintAuthDisabled),
        DECLARE_NAPI_FUNCTION("setDisallowedPolicy", SetDisallowedPolicy),
        DECLARE_NAPI_FUNCTION("getDisallowedPolicy", GetDisallowedPolicy),
        DECLARE_NAPI_FUNCTION("setDisallowedPolicyForAccount", SetDisallowedPolicyForAccount),
        DECLARE_NAPI_FUNCTION("getDisallowedPolicyForAccount", GetDisallowedPolicyForAccount),
        DECLARE_NAPI_FUNCTION("addDisallowedListForAccount", AddDisallowedListForAccount),
        DECLARE_NAPI_FUNCTION("removeDisallowedListForAccount", RemoveDisallowedListForAccount),
        DECLARE_NAPI_FUNCTION("getDisallowedListForAccount", GetDisallowedListForAccount),
        DECLARE_NAPI_FUNCTION("setUserRestriction", SetUserRestriction),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value RestrictionsAddon::SetPrinterDisabled(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "setPrinterDisabled");
    return SetPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_PRINTER);
}

napi_value RestrictionsAddon::SetHdcDisabled(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "setHdcDisabled");
    return SetPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_HDC);
}

void RestrictionsAddon::SetPolicyDisabledCommon(AddonMethodSign &addonMethodSign, int policyCode)
{
    addonMethodSign.name = "SetPolicyDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.policyCode = policyCode;
    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        policyCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG : EdmConstants::PERMISSION_TAG_VERSION_11;
    addonMethodSign.apiVersionTag = permissionTag;
}

napi_value RestrictionsAddon::SetPolicyDisabled(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_SetPolicyDisabled called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "setPolicyDisabled");
    AddonMethodSign addonMethodSign;
    SetPolicyDisabledCommon(addonMethodSign, policyCode);
    return AddonMethodAdapter(env, info, addonMethodSign, NativeSetPolicyDisabled, NativeVoidCallbackComplete);
}

void RestrictionsAddon::NativeSetPolicyDisabled(napi_env env, void *data)
{
    EDMLOGI("NativeSetPolicyDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    asyncCallbackInfo->ret = RestrictionsProxy::GetRestrictionsProxy()->SetDisallowedPolicy(
        asyncCallbackInfo->data, asyncCallbackInfo->policyCode);
}

napi_value RestrictionsAddon::IsPrinterDisabled(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "isPrinterDisabled");
    return IsPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_PRINTER);
}

napi_value RestrictionsAddon::IsHdcDisabled(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "isHdcDisabled");
    return IsPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_HDC);
}

napi_value RestrictionsAddon::IsPolicyDisabled(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_IsPolicyDisabled called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncRestrictionsCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncRestrictionsCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool matchFlag = false;
    if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_null)) {
        asyncCallbackInfo->hasAdmin = false;
        matchFlag = true;
    } else if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object)) {
        matchFlag = true;
        asyncCallbackInfo->hasAdmin = true;
        bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
        ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
        EDMLOGD(
            "IsPolicyDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
            "asyncCallbackInfo->abilityname:%{public}s",
            asyncCallbackInfo->elementName.GetBundleName().c_str(),
            asyncCallbackInfo->elementName.GetAbilityName().c_str());
    }
    if (argc > ARGS_SIZE_ONE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("NAPI_IsPolicyDisabled argc == ARGS_SIZE_TWO");
        NAPI_CALL(env, napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
    }
    asyncCallbackInfo->policyCode = policyCode;
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "IsPolicyDisabled", NativeIsPolicyDisabled, NativeBoolCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void RestrictionsAddon::NativeIsPolicyDisabled(napi_env env, void *data)
{
    EDMLOGI("NativeIsPolicyDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncRestrictionsCallbackInfo *asyncCallbackInfo = static_cast<AsyncRestrictionsCallbackInfo *>(data);
    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        asyncCallbackInfo->policyCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG :
        EdmConstants::PERMISSION_TAG_VERSION_11;
    if (asyncCallbackInfo->hasAdmin) {
        asyncCallbackInfo->ret = RestrictionsProxy::GetRestrictionsProxy()->GetDisallowedPolicy(
            &(asyncCallbackInfo->elementName), asyncCallbackInfo->policyCode, asyncCallbackInfo->boolRet,
            permissionTag);
    } else {
        asyncCallbackInfo->ret = RestrictionsProxy::GetRestrictionsProxy()->GetDisallowedPolicy(
            nullptr, asyncCallbackInfo->policyCode, asyncCallbackInfo->boolRet, permissionTag);
    }
}

napi_value RestrictionsAddon::DisableMicrophone(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "disableMicrophone");
    return SetPolicyDisabledSync(env, info, EdmInterfaceCode::DISABLE_MICROPHONE);
}

napi_value RestrictionsAddon::IsMicrophoneDisabled(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "isMicrophoneDisabled");
    return IsPolicyDisabledSync(env, info, EdmInterfaceCode::DISABLE_MICROPHONE);
}

napi_value RestrictionsAddon::SetFingerprintAuthDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("SetFingerprintAuthDisabled called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "setFingerprintAuthDisabled");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_boolean),
        "parameter disallow error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetFingerprintAuthDisabled: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    bool disallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallow, argv[ARR_INDEX_ONE]), "parameter disallow parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    ErrCode ret = proxy->SetFingerprintAuthDisabled(elementName, disallow);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::IsFingerprintAuthDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsFingerprintAuthDisabled called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "isFingerprintAuthDisabled");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    EDMLOGD("IsFingerprintAuthDisabled: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    bool disallow = false;
    ErrCode ret;
    if (hasAdmin) {
        ret = proxy->IsFingerprintAuthDisabled(&elementName, disallow);
    } else {
        ret = proxy->IsFingerprintAuthDisabled(nullptr, disallow);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, disallow, &result));
    return result;
}

napi_value RestrictionsAddon::SetPolicyDisabledSync(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_SetPolicyDisabledSync called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "setPolicyDisabledSync");
    AddonMethodSign addonMethodSign;
    SetPolicyDisabledCommon(addonMethodSign, policyCode);

    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    ErrCode ret = RestrictionsProxy::GetRestrictionsProxy()->SetDisallowedPolicy(adapterAddonData.data, policyCode);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::IsPolicyDisabledSync(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_IsPolicyDisabled called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "isPolicyDisabledSync");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    ErrCode ret = ERR_OK;
    bool boolRet = false;
    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        policyCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG : EdmConstants::PERMISSION_TAG_VERSION_11;
    if (hasAdmin) {
        ret = RestrictionsProxy::GetRestrictionsProxy()->GetDisallowedPolicy(&elementName, policyCode, boolRet,
            permissionTag);
    } else {
        ret = RestrictionsProxy::GetRestrictionsProxy()->GetDisallowedPolicy(nullptr, policyCode, boolRet,
            permissionTag);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SetPolicyDisabledSync failed!");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, boolRet, &result));
    return result;
}

napi_value RestrictionsAddon::SetDisallowedPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetDisallowedPolicy called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "setDisallowedPolicy");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "parameter feature error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean),
        "parameter disallow error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetDisallowedPolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::string feature;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, feature, argv[ARR_INDEX_ONE]), "parameter feature parse error");
    bool disallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallow, argv[ARR_INDEX_TWO]), "parameter disallow parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    ErrCode ret = ERR_OK;
    if (feature == EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_FINGER_PRINT) {
        ret = proxy->SetFingerprintAuthDisabled(elementName, disallow);
    } else {
        auto labelCode = labelCodeMap.find(feature);
        if (labelCode == labelCodeMap.end()) {
            napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
            return nullptr;
        }
        std::uint32_t ipcCode = labelCode->second;
        std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
            ipcCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG : EdmConstants::PERMISSION_TAG_VERSION_12;
        ret = proxy->SetDisallowedPolicy(elementName, disallow, ipcCode, permissionTag);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::GetDisallowedPolicy(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getDisallowedPolicy");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "parameter feature error");
    std::string feature;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, feature, argv[ARR_INDEX_ONE]), "parameter feature parse error");
    if (hasAdmin) {
        EDMLOGD("GetDisallowedPolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
            elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    } else {
        EDMLOGD("GetDisallowedPolicy: elementName is null");
    }

    bool disallow = false;
    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    ErrCode ret = ERR_OK;
    if (feature == EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_FINGER_PRINT) {
        ret = proxy->IsFingerprintAuthDisabled(hasAdmin ? &elementName : nullptr, disallow);
    } else {
        auto labelCode = labelCodeMap.find(feature);
        if (labelCode == labelCodeMap.end()) {
            napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
            return nullptr;
        }
        std::uint32_t ipcCode = labelCode->second;
        std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
            ipcCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG : EdmConstants::PERMISSION_TAG_VERSION_12;
        ret = proxy->GetDisallowedPolicy(hasAdmin ? &elementName : nullptr, ipcCode, disallow, permissionTag);
    }

    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, disallow, &result));
    return result;
}

napi_value RestrictionsAddon::SetDisallowedPolicyForAccount(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetDisallowedPolicyForAccount called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "setDisallowedPolicyForAccount");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_FOUR, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "parameter feature error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean),
        "parameter disallow error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_THREE], napi_number),
        "parameter accountId error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetDisallowedPolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::string feature;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, feature, argv[ARR_INDEX_ONE]), "parameter feature parse error");
    bool disallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallow, argv[ARR_INDEX_TWO]), "parameter disallow parse error");
    int32_t accountId = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_THREE]),
        "parameter accountId parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    auto labelCode = labelCodeMapForAccount.find(feature);
    if (labelCode == labelCodeMapForAccount.end()) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
        return nullptr;
    }
    std::uint32_t ipcCode = labelCode->second;
    std::string permissionTag = WITHOUT_PERMISSION_TAG;
    ErrCode ret;
    if (ipcCode == EdmInterfaceCode::FINGERPRINT_AUTH) {
        ret = proxy->SetFingerprintAuthDisallowedPolicyForAccount(elementName, disallow,
            ipcCode, permissionTag, accountId);
    } else {
        ret = proxy->SetDisallowedPolicyForAccount(elementName, disallow, ipcCode, permissionTag, accountId);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::GetDisallowedPolicyForAccount(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedPolicyForAccount called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getDisallowedPolicyForAccount");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "parameter feature error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_number),
        "parameter accountId error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    EDMLOGD("SetDisallowedPolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::string feature;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, feature, argv[ARR_INDEX_ONE]), "parameter feature parse error");
    int32_t accountId = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_TWO]), "parameter accountId parse error");

    auto labelCode = labelCodeMapForAccount.find(feature);
    if (labelCode == labelCodeMapForAccount.end()) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
        return nullptr;
    }
    std::uint32_t ipcCode = labelCode->second;
    bool disallow = false;
    ErrCode ret = NativeGetDisallowedPolicyForAccount(hasAdmin, elementName, ipcCode, accountId, disallow);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, disallow, &result));
    return result;
}

OHOS::ErrCode RestrictionsAddon::NativeGetDisallowedPolicyForAccount(bool hasAdmin,
    AppExecFwk::ElementName &elementName, std::uint32_t ipcCode, int32_t accountId, bool &disallow)
{
    std::string permissionTag = WITHOUT_PERMISSION_TAG;
    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (ipcCode == EdmInterfaceCode::FINGERPRINT_AUTH) {
        if (hasAdmin) {
            return proxy->GetFingerprintAuthDisallowedPolicyForAccount(&elementName, ipcCode,
                disallow, permissionTag, accountId);
        } else {
            return proxy->GetFingerprintAuthDisallowedPolicyForAccount(nullptr, ipcCode,
                disallow, permissionTag, accountId);
        }
    } else {
        if (!hasAdmin) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        return proxy->GetDisallowedPolicyForAccount(elementName, ipcCode, disallow, permissionTag, accountId);
    }
}

napi_value RestrictionsAddon::AddDisallowedListForAccount(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "addDisallowedListForAccount");
    return AddOrRemoveDisallowedListForAccount(env, info, true);
}

napi_value RestrictionsAddon::RemoveDisallowedListForAccount(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "removeDisallowedListForAccount");
    return AddOrRemoveDisallowedListForAccount(env, info, false);
}

napi_value RestrictionsAddon::GetDisallowedListForAccount(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedListForAccount called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getDisallowedListForAccount");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "param admin need be want");
    std::string feature;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, feature, argv[ARR_INDEX_ONE]), "parameter feature parse error");

    int32_t accountId = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_TWO]), "parameter accountId parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    std::vector<std::string> resultArray;
    ErrCode ret = proxy->GetDisallowedListForAccount(elementName, feature, accountId, resultArray);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_array(env, &result));
    ConvertStringVectorToJS(env, resultArray, result);
    return result;
}

napi_value RestrictionsAddon::AddOrRemoveDisallowedListForAccount(napi_env env, napi_callback_info info,
    bool isAdd)
{
    EDMLOGI("NAPI_AddOrRemoveDisallowedListForAccount called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_FOUR, "parameter count error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetDisallowedPolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::string feature;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, feature, argv[ARR_INDEX_ONE]), "parameter feature parse error");
    std::vector<std::string> bundleNameArray;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, bundleNameArray, argv[ARR_INDEX_TWO]),
        "parameter bundle name error");
    int32_t accountId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_THREE]),
        "parameter accountId parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    ErrCode ret = proxy->AddOrRemoveDisallowedListForAccount(elementName, feature, bundleNameArray, accountId, isAdd);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::SetUserRestriction(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetUserRestriction called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string),
        "parameter settingsItem error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean),
        "parameter disallow error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetUserRestriction: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::string settingsItem;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, settingsItem, argv[ARR_INDEX_ONE]),
        "parameter settingsItem parse error");
    bool disallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallow, argv[ARR_INDEX_TWO]), "parameter disallow parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    ErrCode ret = ERR_OK;
    auto itemCode = itemCodeMap.find(settingsItem);
    if (itemCode == itemCodeMap.end()) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
        return nullptr;
    }
    std::uint32_t ipcCode = itemCode->second;
    ret = proxy->SetUserRestriction(elementName, disallow, ipcCode);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

static napi_module g_restrictionsModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = RestrictionsAddon::Init,
    .nm_modname = "enterprise.restrictions",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RestrictionsRegister()
{
    napi_module_register(&g_restrictionsModule);
}
