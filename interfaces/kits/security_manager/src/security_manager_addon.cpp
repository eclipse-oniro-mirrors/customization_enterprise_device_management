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

#include "security_manager_addon.h"

#include "cJSON.h"
#include "device_settings_proxy.h"
#include "edm_constants.h"
#include "edm_log.h"

using namespace OHOS::EDM;

napi_value SecurityManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("getSecurityPatchTag", GetSecurityPatchTag),
        DECLARE_NAPI_FUNCTION("getDeviceEncryptionStatus", GetDeviceEncryptionStatus),
        DECLARE_NAPI_FUNCTION("setPasswordPolicy", SetPasswordPolicy),
        DECLARE_NAPI_FUNCTION("getPasswordPolicy", GetPasswordPolicy),
        DECLARE_NAPI_FUNCTION("getSecurityStatus", GetSecurityStatus),
        DECLARE_NAPI_FUNCTION("installUserCertificate", InstallUserCertificate),
        DECLARE_NAPI_FUNCTION("uninstallUserCertificate", UninstallUserCertificate),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value SecurityManagerAddon::GetSecurityPatchTag(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetSecurityPatchTag called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter type error");
    bool boolret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, boolret, "element name param error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    std::string stringRet;
    auto securityManagerProxy = SecurityManagerProxy::GetSecurityManagerProxy();
    int32_t ret = securityManagerProxy->GetSecurityPatchTag(elementName, stringRet);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value securityPatchTag;
    napi_create_string_utf8(env, stringRet.c_str(), stringRet.size(), &securityPatchTag);
    return securityPatchTag;
}

napi_value SecurityManagerAddon::GetDeviceEncryptionStatus(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDeviceEncryptionStatus called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisArg = nullptr;
    void* data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter type error");
    bool boolret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, boolret, "element name param error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    DeviceEncryptionStatus deviceEncryptionStatus;
    auto securityManagerProxy = SecurityManagerProxy::GetSecurityManagerProxy();
    int32_t ret = securityManagerProxy->GetDeviceEncryptionStatus(elementName, deviceEncryptionStatus);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return ConvertDeviceEncryptionStatus(env, deviceEncryptionStatus);
}

napi_value SecurityManagerAddon::ConvertDeviceEncryptionStatus(napi_env env,
    DeviceEncryptionStatus &deviceEncryptionStatus)
{
    napi_value objDeviceEncryptionStatus = nullptr;
    napi_create_object(env, &objDeviceEncryptionStatus);
    napi_value nIsEncrypted;
    napi_get_boolean(env, deviceEncryptionStatus.isEncrypted, &nIsEncrypted);
    napi_set_named_property(env, objDeviceEncryptionStatus, "isEncrypted", nIsEncrypted);
    return objDeviceEncryptionStatus;
}

napi_value SecurityManagerAddon::SetPasswordPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetPasswordPolicy called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisArg = nullptr;
    void* data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "admin type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_object),
        "passwordPolicy type error");

    PasswordPolicy policy;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env,
        JsObjectToString(env, argv[ARR_INDEX_ONE], "complexityRegex", false, policy.complexityReg),
        "Parameter passwordPolicy error");
    ASSERT_AND_THROW_PARAM_ERROR(env,
        JsObjectToInt(env, argv[ARR_INDEX_ONE], "validityPeriod", false, policy.validityPeriod),
        "Parameter passwordPolicy error");
    ASSERT_AND_THROW_PARAM_ERROR(env,
        JsObjectToString(env, argv[ARR_INDEX_ONE], "additionalDescription", false, policy.additionalDescription),
        "Parameter passwordPolicy error");
    int32_t retCode = SecurityManagerProxy::GetSecurityManagerProxy()->SetPasswordPolicy(elementName, policy);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

napi_value SecurityManagerAddon::GetPasswordPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetPasswordPolicy called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisArg = nullptr;
    void* data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "admin type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "Parameter admin error");

    PasswordPolicy policy;
    int32_t retCode = SecurityManagerProxy::GetSecurityManagerProxy()->GetPasswordPolicy(elementName, policy);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
        return nullptr;
    }
    napi_value ret;
    napi_value complexityReg;
    napi_value validityPeriod;
    napi_value additionalDescription;
    napi_create_object(env, &ret);
    napi_create_string_utf8(env, policy.complexityReg.c_str(), NAPI_AUTO_LENGTH, &complexityReg);
    napi_create_int32(env, policy.validityPeriod, &validityPeriod);
    napi_create_string_utf8(env, policy.additionalDescription.c_str(), NAPI_AUTO_LENGTH, &additionalDescription);
    napi_set_named_property(env, ret, "complexityRegex", complexityReg);
    napi_set_named_property(env, ret, "validityPeriod", validityPeriod);
    napi_set_named_property(env, ret, "additionalDescription", additionalDescription);
    return ret;
}

napi_value SecurityManagerAddon::GetSecurityStatus(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetSecurityStatus called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisArg = nullptr;
    void* data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string),
        "The second parameter must be string.");
    bool boolret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, boolret, "element name param error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    std::string item;
    boolret = ParseString(env, item, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, boolret, "param 'item' parse error");
    std::string stringRet;
    auto securityManagerProxy = SecurityManagerProxy::GetSecurityManagerProxy();
    int32_t ret = ERR_OK;
    if (item == EdmConstants::SecurityManager::PATCH) {
        ret = securityManagerProxy->GetSecurityPatchTag(elementName, stringRet);
    } else if (item == EdmConstants::SecurityManager::ENCRYPTION) {
        DeviceEncryptionStatus deviceEncryptionStatus;
        ret = securityManagerProxy->GetDeviceEncryptionStatus(elementName, deviceEncryptionStatus);
        if (SUCCEEDED(ret)) {
            ret = ConvertDeviceEncryptionToJson(env, deviceEncryptionStatus, stringRet);
        }
    } else if (item == EdmConstants::SecurityManager::ROOT) {
        ret = securityManagerProxy->GetRootCheckStatus(elementName, stringRet);
    } else {
        ret = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value status;
    napi_create_string_utf8(env, stringRet.c_str(), stringRet.size(), &status);
    return status;
}

int32_t SecurityManagerAddon::ConvertDeviceEncryptionToJson(napi_env env,
    DeviceEncryptionStatus &deviceEncryptionStatus, std::string &stringRet)
{
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    cJSON_AddBoolToObject(json, "isEncrypted", deviceEncryptionStatus.isEncrypted);
    char *jsonStr = cJSON_PrintUnformatted(json);
    if (jsonStr == nullptr) {
        cJSON_Delete(json);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    stringRet = std::string(jsonStr);
    cJSON_Delete(json);
    cJSON_free(jsonStr);
    return ERR_OK;
}

napi_value SecurityManagerAddon::InstallUserCertificate(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_InstallUserCertificate called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter want error");
    matchFlag = MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter certblob error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCertCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncCertCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool retAdmin = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, retAdmin, "element name param error");
    EDMLOGD(
        "InstallUserCertificate: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());

    bool retCertBlob = ParseCertBlob(env, argv[ARR_INDEX_ONE], asyncCallbackInfo);
    ASSERT_AND_THROW_PARAM_ERROR(env, retCertBlob, "element cert blob error");

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "InstallUserCertificate",
        NativeInstallUserCertificate, NativeStringCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void SecurityManagerAddon::NativeInstallUserCertificate(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeInstallUserCertificate called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCertCallbackInfo *asyncCallbackInfo = static_cast<AsyncCertCallbackInfo *>(data);
    asyncCallbackInfo->ret = DeviceSettingsProxy::GetDeviceSettingsProxy()->InstallUserCertificate(
        asyncCallbackInfo->elementName, asyncCallbackInfo->certArray, asyncCallbackInfo->alias,
        asyncCallbackInfo->stringRet, asyncCallbackInfo->innerCodeMsg);
}

napi_value SecurityManagerAddon::UninstallUserCertificate(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_UninstallUserCertificate called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter want error");
    matchFlag = MatchValueType(env, argv[ARR_INDEX_ONE], napi_string);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter uri error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCertCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncCertCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool retAdmin = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, retAdmin, "element name param error");
    EDMLOGD(
        "UninstallUserCertificate: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());

    bool retAlias = ParseString(env, asyncCallbackInfo->alias, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, retAlias, "element alias error");

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "uninstallUserCertificate",
        NativeUninstallUserCertificate, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void SecurityManagerAddon::NativeUninstallUserCertificate(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeUninstallUserCertificate called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCertCallbackInfo *asyncCallbackInfo = static_cast<AsyncCertCallbackInfo *>(data);
    asyncCallbackInfo->ret = DeviceSettingsProxy::GetDeviceSettingsProxy()->UninstallUserCertificate(
        asyncCallbackInfo->elementName, asyncCallbackInfo->alias, asyncCallbackInfo->innerCodeMsg);
}

bool SecurityManagerAddon::ParseCertBlob(napi_env env, napi_value object, AsyncCertCallbackInfo *asyncCertCallbackInfo)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, object, &type), false);
    if (type != napi_object) {
        EDMLOGE("type of param certblob is not object");
        return false;
    }
    if (!JsObjectToU8Vector(env, object, "inData", asyncCertCallbackInfo->certArray)) {
        EDMLOGE("uint8Array to vector failed");
        return false;
    }
    return JsObjectToString(env, object, "alias", true, asyncCertCallbackInfo->alias);
}

static napi_module g_securityModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = SecurityManagerAddon::Init,
    .nm_modname = "enterprise.securityManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void SecurityManagerRegister()
{
    napi_module_register(&g_securityModule);
}
