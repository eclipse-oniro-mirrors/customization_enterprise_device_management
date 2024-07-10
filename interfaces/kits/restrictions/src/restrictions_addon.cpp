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
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SCREENSHOT, EdmInterfaceCode::POLICY_CODE_END + 11},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SCREEN_RECORD, EdmInterfaceCode::POLICY_CODE_END + 12},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_DISK_RECOVERY_KEY, EdmInterfaceCode::POLICY_CODE_END + 17},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_NEAR_LINK, EdmInterfaceCode::POLICY_CODE_END + 18},
};

std::vector<uint32_t> RestrictionsAddon::multiPermCodes = {
    EdmInterfaceCode::DISABLE_BLUETOOTH,
    EdmInterfaceCode::DISALLOW_MODIFY_DATETIME,
    EdmInterfaceCode::DISABLED_PRINTER,
    EdmInterfaceCode::DISABLED_HDC,
    EdmInterfaceCode::DISABLE_USB,
    EdmInterfaceCode::DISABLE_WIFI,
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
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value RestrictionsAddon::SetPrinterDisabled(napi_env env, napi_callback_info info)
{
    return SetPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_PRINTER);
}

napi_value RestrictionsAddon::SetHdcDisabled(napi_env env, napi_callback_info info)
{
    return SetPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_HDC);
}

napi_value RestrictionsAddon::SetPolicyDisabled(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_SetPolicyDisabled called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_boolean);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasPolicy, "The second parameter must be bool.");
    if (argc > ARGS_SIZE_TWO) {
        bool hasCallback = MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
        ASSERT_AND_THROW_PARAM_ERROR(env, hasCallback, "The third parameter must be function");
    }
    auto asyncCallbackInfo = new (std::nothrow) AsyncRestrictionsCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncRestrictionsCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD(
        "SetPolicyDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ret = ParseBool(env, asyncCallbackInfo->isDisabled, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "isDisabled param error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_SetPolicyDisabled argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARR_INDEX_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    asyncCallbackInfo->policyCode = policyCode;
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "SetPolicyDisabled", NativeSetPolicyDisabled,
        NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void RestrictionsAddon::NativeSetPolicyDisabled(napi_env env, void *data)
{
    EDMLOGI("NativeSetPolicyDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncRestrictionsCallbackInfo *asyncCallbackInfo = static_cast<AsyncRestrictionsCallbackInfo *>(data);
    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        asyncCallbackInfo->policyCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG :
        EdmConstants::PERMISSION_TAG_VERSION_11;
    asyncCallbackInfo->ret = RestrictionsProxy::GetRestrictionsProxy()->SetDisallowedPolicy(
        asyncCallbackInfo->elementName, asyncCallbackInfo->isDisabled, asyncCallbackInfo->policyCode, permissionTag);
}

napi_value RestrictionsAddon::IsPrinterDisabled(napi_env env, napi_callback_info info)
{
    return IsPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_PRINTER);
}

napi_value RestrictionsAddon::IsHdcDisabled(napi_env env, napi_callback_info info)
{
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
        napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
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
    return SetPolicyDisabledSync(env, info, EdmInterfaceCode::DISABLE_MICROPHONE);
}

napi_value RestrictionsAddon::IsMicrophoneDisabled(napi_env env, napi_callback_info info)
{
    return IsPolicyDisabledSync(env, info, EdmInterfaceCode::DISABLE_MICROPHONE);
}

napi_value RestrictionsAddon::SetFingerprintAuthDisabled(napi_env env, napi_callback_info info)
{
    return SetPolicyDisabledSync(env, info, EdmInterfaceCode::FINGERPRINT_AUTH);
}

napi_value RestrictionsAddon::IsFingerprintAuthDisabled(napi_env env, napi_callback_info info)
{
    return IsPolicyDisabledSync(env, info, EdmInterfaceCode::FINGERPRINT_AUTH);
}

napi_value RestrictionsAddon::SetPolicyDisabledSync(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_SetPolicyDisabledSync called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_boolean), "parameter bool error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    bool isDisallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, isDisallow, argv[ARR_INDEX_ONE]), "bool name param error");

    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        policyCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG : EdmConstants::PERMISSION_TAG_VERSION_11;
    ErrCode ret = RestrictionsProxy::GetRestrictionsProxy()->SetDisallowedPolicy(elementName, isDisallow, policyCode,
        permissionTag);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::IsPolicyDisabledSync(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_IsPolicyDisabled called");
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
    napi_get_boolean(env, boolRet, &result);
    return result;
}

napi_value RestrictionsAddon::SetDisallowedPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetDisallowedPolicy called");
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
        return nullptr;
    }
    auto labelCode = labelCodeMap.find(feature);
    if (labelCode == labelCodeMap.end()) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
        return nullptr;
    }
    std::uint32_t ipcCode = labelCode->second;
    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        ipcCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG : EdmConstants::PERMISSION_TAG_VERSION_12;
    ErrCode ret = proxy->SetDisallowedPolicy(elementName, disallow, ipcCode, permissionTag);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::GetDisallowedPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedPolicy called");
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
        return nullptr;
    }
    auto labelCode = labelCodeMap.find(feature);
    if (labelCode == labelCodeMap.end()) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
        return nullptr;
    }
    std::uint32_t ipcCode = labelCode->second;
    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        ipcCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG : EdmConstants::PERMISSION_TAG_VERSION_12;
    ErrCode ret = ERR_OK;
    if (hasAdmin) {
        ret = proxy->GetDisallowedPolicy(&elementName, ipcCode, disallow, permissionTag);
    } else {
        ret = proxy->GetDisallowedPolicy(nullptr, ipcCode, disallow, permissionTag);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_boolean(env, disallow, &result);
    return result;
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
