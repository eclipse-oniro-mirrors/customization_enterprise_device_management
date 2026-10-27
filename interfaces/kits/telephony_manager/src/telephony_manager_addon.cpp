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
#include "iptables_utils.h"
#include "napi_edm_common.h"
#include "sms_message_info.h"

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
        DECLARE_NAPI_FUNCTION("hangupCalling", HangupCalling),
        DECLARE_NAPI_FUNCTION("activeSim", ActiveSim),
        DECLARE_NAPI_FUNCTION("deactiveSim", DeactiveSim),
        DECLARE_NAPI_FUNCTION("setDefaultData", SetDefaultDataSim),
        DECLARE_NAPI_FUNCTION("getDefaultData", GetDefaultDataSim),
        DECLARE_NAPI_FUNCTION("getCallLogs", GetCallLogs),
        DECLARE_NAPI_FUNCTION("getSmsMessages", GetSmsMessages),
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
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::UINT32};
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
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::UINT32};
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

napi_value TelephonyManagerAddon::GetCallPolicyNumbersCommon(napi_env env, napi_callback_info info,
    const std::string &callPolicyType, const std::string &methodName)
{
    EDMLOGI("NAPI_%{public}s called", methodName.c_str());
#if defined(TELEPHONY_EDM_ENABLE)
    auto convertPolicy2Data = [callPolicyType](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) -> ErrCode {
        int32_t policy = -1;
        bool isNumber = ParseInt(env, policy, argv);
        if (!isNumber) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        data.WriteString(callPolicyType);
        data.WriteInt32(policy);
        return ERR_OK;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = methodName;
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {nullptr, convertPolicy2Data};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    std::vector<std::string> numbers;
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->GetCallPolicyNumbers(
        adapterAddonData.data, numbers);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value jsList = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, numbers.size(), &jsList));
    ConvertStringVectorToJS(env, numbers, jsList);
    return jsList;
#else
    EDMLOGW("TelephonyManagerAddon::%{public}s Unsupported Capabilities.", methodName.c_str());
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::GetOutgoingCallPolicyNumbers(napi_env env, napi_callback_info info)
{
    return GetCallPolicyNumbersCommon(env, info, EdmConstants::CallPolicy::OUTGOING, "GetOutgoingCallPolicyNumbers");
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
    return GetCallPolicyNumbersCommon(env, info, EdmConstants::CallPolicy::INCOMING, "GetIncomingCallPolicyNumbers");
}

napi_value TelephonyManagerAddon::HangupCalling(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_HangupCalling called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "hangupCalling";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->HangupCalling(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::HangupCalling Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::ActiveSim(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_ActiveSim called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "activeSim";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::UINT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->ActiveSim(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, ErrcodeType::NUMBER));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::ActiveSim Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED, ErrcodeType::NUMBER));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::DeactiveSim(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_DeactiveSim called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "deactiveSim";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::UINT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->DeactiveSim(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, ErrcodeType::NUMBER));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::DeactiveSim Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED, ErrcodeType::NUMBER));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::SetDefaultDataSim(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetDefaultDataSim called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "setDefaultDataSim";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::UINT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->SetDefaultDataSim(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, ErrcodeType::NUMBER));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::SetDefaultDataSim Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED, ErrcodeType::NUMBER));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::GetDefaultDataSim(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDefaultDataSim called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "getDefaultDataSim";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t simId = -1;
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->GetDefaultDataSim(adapterAddonData.data, simId);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, ErrcodeType::NUMBER));
        return nullptr;
    }

    napi_value jsResult = nullptr;
    NAPI_CALL(env, napi_create_int32(env, simId, &jsResult));
    return jsResult;
#else
    EDMLOGW("TelephonyManagerAddon::GetDefaultDataSim Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED, ErrcodeType::NUMBER));
    return nullptr;
#endif
}

#if defined(TELEPHONY_EDM_ENABLE)
static bool ParseQueryConfigFromJs(napi_env env, napi_value argv, TelephonyQueryConfig &config)
{
    napi_value startTimeValue = nullptr;
    napi_get_named_property(env, argv, "startTime", &startTimeValue);
    napi_valuetype startTimeType = napi_undefined;
    napi_typeof(env, startTimeValue, &startTimeType);
    if (startTimeType != napi_number) {
        return false;
    }
    napi_get_value_int64(env, startTimeValue, &config.startTime);
    napi_value endTimeValue = nullptr;
    napi_get_named_property(env, argv, "endTime", &endTimeValue);
    napi_valuetype endTimeType = napi_undefined;
    napi_typeof(env, endTimeValue, &endTimeType);
    if (endTimeType != napi_number) {
        return false;
    }
    napi_get_value_int64(env, endTimeValue, &config.endTime);
    bool hasTelephoneNumber = false;
    napi_has_named_property(env, argv, "telephoneNumber", &hasTelephoneNumber);
    config.hasTelephoneNumber = hasTelephoneNumber;
    if (!hasTelephoneNumber) {
        return true;
    }
    napi_value telValue = nullptr;
    napi_get_named_property(env, argv, "telephoneNumber", &telValue);
    napi_valuetype telType = napi_undefined;
    napi_typeof(env, telValue, &telType);
    if (telType == napi_string) {
        size_t len = 0;
        napi_get_value_string_utf8(env, telValue, nullptr, 0, &len);
        if (len == 0) {
            return false;
        }
        config.telephoneNumber.resize(len);
        napi_get_value_string_utf8(env, telValue, config.telephoneNumber.data(), len + 1, &len);
    } else if (telType != napi_undefined) {
        return false;
    }
    return true;
}
#endif

napi_value TelephonyManagerAddon::GetCallLogs(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetCallLogs called");
#ifdef FEATURE_PC_ONLY
    EDMLOGW("TelephonyManagerAddon::GetCallLogs not supported on PC.");
    return NapiThrowErrorAsync(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
#elif defined(TELEPHONY_EDM_ENABLE)
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallLogCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncCallLogCallbackInfo> callbackPtr{asyncCallbackInfo};
    if (argc < ARGS_SIZE_TWO) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, ErrcodeType::NUMBER));
        return nullptr;
    }
    if (!MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object)) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, ErrcodeType::NUMBER));
        return nullptr;
    }
    if (!ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO])) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, ErrcodeType::NUMBER));
        return nullptr;
    }
    if (!MatchValueType(env, argv[ARR_INDEX_ONE], napi_object) ||
        !ParseQueryConfigFromJs(env, argv[ARR_INDEX_ONE], asyncCallbackInfo->queryConfig)) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, ErrcodeType::NUMBER));
        return nullptr;
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "NativeGetCallLogs",
        NativeGetCallLogs, NativeGetCallLogsComplete);
    callbackPtr.release();
    return asyncWorkReturn;
#else
    EDMLOGW("TelephonyManagerAddon::GetCallLogs Unsupported Capabilities.");
    return NapiThrowErrorAsync(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
#endif
}

void TelephonyManagerAddon::NativeGetCallLogs(napi_env env, void *data)
{
    if (data == nullptr) {
        EDMLOGE("NativeGetCallLogs: data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncCallLogCallbackInfo *>(data);
    auto proxy = TelephonyManagerProxy::GetTelephonyManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("NativeGetCallLogs: proxy is nullptr");
        asyncCallbackInfo->ret = EdmReturnErrCode::EXECUTE_TIME_OUT;
        return;
    }
    asyncCallbackInfo->ret = proxy->GetCallLogs(asyncCallbackInfo->elementName,
        asyncCallbackInfo->queryConfig, asyncCallbackInfo->callLogs);
}

void TelephonyManagerAddon::NativeGetCallLogsComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("NativeGetCallLogsComplete: data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncCallLogCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_value jsArray = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &jsArray));
            ConvertVectorCallLogToJs(env, asyncCallbackInfo->callLogs, jsArray);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, jsArray);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred,
                CreateError(env, asyncCallbackInfo->ret, ErrcodeType::NUMBER));
        }
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

void TelephonyManagerAddon::ConvertVectorCallLogToJs(napi_env env,
    const std::vector<CallLogInfo> &callLogs, napi_value &result)
{
    if (callLogs.empty()) {
        EDMLOGI("ConvertVectorCallLogToJs: empty");
        return;
    }
    size_t index = 0;
    for (const auto &log : callLogs) {
        napi_value jsLog = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &jsLog));
        napi_value jsCreateTime = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, log.createTime, &jsCreateTime));
        napi_set_named_property(env, jsLog, "createTime", jsCreateTime);
        napi_value jsStartTime = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, log.startTime, &jsStartTime));
        napi_set_named_property(env, jsLog, "startTime", jsStartTime);
        napi_value jsEndTime = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, log.endTime, &jsEndTime));
        napi_set_named_property(env, jsLog, "endTime", jsEndTime);
        napi_value jsIsIncoming = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, log.isIncoming, &jsIsIncoming));
        napi_set_named_property(env, jsLog, "isIncoming", jsIsIncoming);
        napi_value jsSlotId = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, log.slotId, &jsSlotId));
        napi_set_named_property(env, jsLog, "slotId", jsSlotId);
        napi_value jsTelNumber = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, log.telephoneNumber.c_str(),
            NAPI_AUTO_LENGTH, &jsTelNumber));
        napi_set_named_property(env, jsLog, "telephoneNumber", jsTelNumber);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, jsLog));
        index++;
    }
}

void TelephonyManagerAddon::ConvertVectorSmsMessageToJs(napi_env env,
    const std::vector<SmsMessageInfo> &messages, napi_value &result)
{
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, messages.size(), &result));
    for (size_t i = 0; i < messages.size(); ++i) {
        napi_value jsItem = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &jsItem));

        napi_value nSlotId = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, messages[i].slotId, &nSlotId));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsItem, "slotId", nSlotId));

        napi_value nTelephoneNumber = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, messages[i].telephoneNumber.c_str(),
            NAPI_AUTO_LENGTH, &nTelephoneNumber));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsItem, "telephoneNumber", nTelephoneNumber));

        napi_value nContent = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, messages[i].content.c_str(),
            NAPI_AUTO_LENGTH, &nContent));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsItem, "content", nContent));

        napi_value nTime = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, messages[i].timer, &nTime));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsItem, "time", nTime));

        napi_value nIsSender = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, messages[i].isSender, &nIsSender));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsItem, "isSender", nIsSender));

        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, static_cast<uint32_t>(i), jsItem));
    }
}

napi_value TelephonyManagerAddon::GetSmsMessages(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetSmsMessages called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    auto asyncCallbackInfo = new (std::nothrow) AsyncSmsMessageCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSmsMessageCallbackInfo> callbackPtr{asyncCallbackInfo};
    if (argc < ARGS_SIZE_ONE) {
        return NapiThrowErrorAsync(env, EdmReturnErrCode::PARAM_ERROR);
    }
    if (!MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) ||
        !ParseQueryConfigFromJs(env, argv[ARR_INDEX_ZERO], asyncCallbackInfo->queryConfig)) {
        return NapiThrowErrorAsync(env, EdmReturnErrCode::PARAM_ERROR);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "NativeGetSmsMessages",
        NativeGetSmsMessages, NativeGetSmsMessagesComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void TelephonyManagerAddon::NativeGetSmsMessages(napi_env env, void *data)
{
    if (data == nullptr) {
        EDMLOGE("NativeGetSmsMessages: data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncSmsMessageCallbackInfo *>(data);
    auto proxy = TelephonyManagerProxy::GetTelephonyManagerProxy();
    if (proxy == nullptr) {
        EDMLOGE("NativeGetSmsMessages: proxy is nullptr");
        asyncCallbackInfo->ret = EdmReturnErrCode::EXECUTE_TIME_OUT;
        return;
    }
    asyncCallbackInfo->ret = proxy->GetSmsMessages(asyncCallbackInfo->queryConfig, asyncCallbackInfo->messages);
}

void TelephonyManagerAddon::NativeGetSmsMessagesComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("NativeGetSmsMessagesComplete: data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncSmsMessageCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_value jsArray = nullptr;
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &jsArray));
            ConvertVectorSmsMessageToJs(env, asyncCallbackInfo->messages, jsArray);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, jsArray);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred,
                CreateError(env, asyncCallbackInfo->ret, ErrcodeType::NUMBER));
        }
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
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