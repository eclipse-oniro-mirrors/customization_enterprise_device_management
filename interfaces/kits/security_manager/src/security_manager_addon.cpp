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

#include "security_manager_addon.h"

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
        JsObjectToString(env, argv[ARR_INDEX_ONE], "complexityReg", false, policy.complexityReg),
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
    napi_set_named_property(env, ret, "complexityReg", complexityReg);
    napi_set_named_property(env, ret, "validityPeriod", validityPeriod);
    napi_set_named_property(env, ret, "additionalDescription", additionalDescription);
    return ret;
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
