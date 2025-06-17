/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "telephony_manager_addon.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "hisysevent_adapter.h"
#include "iptables_utils.h"

using namespace OHOS::EDM;
constexpr int32_t STRING_MAX_LEN = 100;

napi_value TelephonyManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setSimDisabled", SetSimDisabled),
        DECLARE_NAPI_FUNCTION("setSimEnabled", SetSimEnabled),
        DECLARE_NAPI_FUNCTION("isSimDisabled", IsSimDisabled),
        DECLARE_NAPI_FUNCTION("addOutgoingCallPolicyNumbers", AddOutgoingCallPolicyNumbers),
        DECLARE_NAPI_FUNCTION("removeOutgoingCallPolicyNumbers", RemoveOutgoingCallPolicyNumbers),
        DECLARE_NAPI_FUNCTION("getOutgoingCallPolicyNumbers", GetOutgoingCallPolicyNumbers),
        DECLARE_NAPI_FUNCTION("addIncomingCallPolicyNumbers", AddIncomingCallPolicyNumbers),
        DECLARE_NAPI_FUNCTION("removeIncomingCallPolicyNumbers", RemoveIncomingCallPolicyNumbers),
        DECLARE_NAPI_FUNCTION("getIncomingCallPolicyNumbers", GetIncomingCallPolicyNumbers),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}


napi_value TelephonyManagerAddon::SetSimDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetSimDisabled called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "setSimDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->SetSimDisabled(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::SetSimDisabled Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::SetSimEnabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetSimEnabled called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "setSimEnabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->SetSimEnabled(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::SetSimEnabled Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::IsSimDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsSimDisabled called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "isSimDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    bool isDisable = false;
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->IsSimDisabled(adapterAddonData.data, isDisable);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isDisable, &result));
    return result;
#else
    EDMLOGW("TelephonyManagerAddon::IsSimDisabled Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

bool TelephonyManagerAddon::CheckVectorStringLength(const std::vector<std::string> &array)
{
    for (const auto &item : array) {
        if (item.empty() || item.length() > STRING_MAX_LEN) {
            return false;
        }
    }
    return true;
}

napi_value TelephonyManagerAddon::AddOutgoingCallPolicyNumbers(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddOutgoingCallPolicyNumbers called");
#if defined(TELEPHONY_EDM_ENABLE)
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasPolicy, "The second parameter must be Policy.");
    bool hasNumbers = MatchValueType(env, argv[ARR_INDEX_TWO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasNumbers, "The third parameter must be numbers.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    int32_t policy = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, policy, argv[ARR_INDEX_ONE]),
        "element name param error");
    std::vector<std::string> numbers;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, numbers, argv[ARR_INDEX_TWO]),
        "apnInfo name param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckVectorStringLength(numbers), "string length is limit");

    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->AddCallPolicyNumbers(
        elementName, EdmConstants::CallPolicy::OUTGOING, policy, numbers);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::AddOutgoingCallPolicyNumbers Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::RemoveOutgoingCallPolicyNumbers(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveOutgoingCallPolicyNumbers called");
#if defined(TELEPHONY_EDM_ENABLE)
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasPolicy, "The second parameter must be Policy.");
    bool hasNumbers = MatchValueType(env, argv[ARR_INDEX_TWO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasNumbers, "The third parameter must be numbers.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    int32_t policy = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, policy, argv[ARR_INDEX_ONE]),
        "element name param error");
    std::vector<std::string> numbers;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, numbers, argv[ARR_INDEX_TWO]),
        "apnInfo name param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckVectorStringLength(numbers), "string length is limit");

    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->RemoveCallPolicyNumbers(
        elementName, EdmConstants::CallPolicy::OUTGOING, policy, numbers);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::RemoveOutgoingCallPolicyNumbers Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::GetOutgoingCallPolicyNumbers(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetOutgoingCallPolicyNumbers called");
#if defined(TELEPHONY_EDM_ENABLE)
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasPolicy, "The second parameter must be Policy.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    int32_t policy = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, policy, argv[ARR_INDEX_ONE]),
        "element name param error");

    std::vector<std::string> numbers;
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->GetCallPolicyNumbers(
        elementName, EdmConstants::CallPolicy::OUTGOING, policy, numbers);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }

    napi_value jsList = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, numbers.size(), &jsList));
    ConvertStringVectorToJS(env, numbers, jsList);

    return jsList;
#else
    EDMLOGW("TelephonyManagerAddon::GetOutgoingCallPolicyNumbers Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::AddIncomingCallPolicyNumbers(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddIncomingCallPolicyNumbers called");
#if defined(TELEPHONY_EDM_ENABLE)
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasPolicy, "The second parameter must be Policy.");
    bool hasNumbers = MatchValueType(env, argv[ARR_INDEX_TWO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasNumbers, "The third parameter must be numbers.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    int32_t policy = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, policy, argv[ARR_INDEX_ONE]),
        "element name param error");
    std::vector<std::string> numbers;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, numbers, argv[ARR_INDEX_TWO]),
        "apnInfo name param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckVectorStringLength(numbers), "string length is limit");

    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->AddCallPolicyNumbers(
        elementName, EdmConstants::CallPolicy::INCOMING, policy, numbers);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::AddIncomingCallPolicyNumbers Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::RemoveIncomingCallPolicyNumbers(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveIncomingCallPolicyNumbers called");
#if defined(TELEPHONY_EDM_ENABLE)
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasPolicy, "The second parameter must be Policy.");
    bool hasNumbers = MatchValueType(env, argv[ARR_INDEX_TWO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasNumbers, "The third parameter must be numbers.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    int32_t policy = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, policy, argv[ARR_INDEX_ONE]),
        "element name param error");
    std::vector<std::string> numbers;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, numbers, argv[ARR_INDEX_TWO]),
        "apnInfo name param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckVectorStringLength(numbers), "string length is limit");

    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->RemoveCallPolicyNumbers(
        elementName, EdmConstants::CallPolicy::INCOMING, policy, numbers);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::RemoveIncomingCallPolicyNumbers Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::GetIncomingCallPolicyNumbers(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetIncomingCallPolicyNumbers called");
#if defined(TELEPHONY_EDM_ENABLE)
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "The first parameter must be want.");
    bool hasPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasPolicy, "The second parameter must be Policy.");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    int32_t policy = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, policy, argv[ARR_INDEX_ONE]),
        "element name param error");

    std::vector<std::string> numbers;
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->GetCallPolicyNumbers(
        elementName, EdmConstants::CallPolicy::INCOMING, policy, numbers);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }

    napi_value jsList = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, numbers.size(), &jsList));
    ConvertStringVectorToJS(env, numbers, jsList);

    return jsList;
#else
    EDMLOGW("TelephonyManagerAddon::GetIncomingCallPolicyNumbers Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

static napi_module g_telephonyManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = TelephonyManagerAddon::Init,
    .nm_modname = "enterprise.telephonyManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void TelephonyManagerRegister()
{
    napi_module_register(&g_telephonyManagerModule);
}